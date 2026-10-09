use std::{
    collections::HashSet,
    error::Error,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use solana_ledger::shred::ReedSolomonCache;
use solana_perf::{
    deduper::Deduper,
    packet::PacketBatchRecycler,
    recycler::Recycler,
};
use solana_pubkey::Pubkey;
use solana_sdk::clock::Slot;
use solana_streamer::streamer::{self, StreamerReceiveStats};
use tokio::task;
use tracing::{info, warn};

use crate::{
    config::{Config, Endpoint},
    deshred::{self, ComparableShred, DeshredMetrics, ShredsStateTracker},
    utils::{TransactionData, get_current_timestamp},
};

use super::{
    GeyserProvider, ProviderContext,
    common::{TransactionAccumulator, build_signature_envelope, enqueue_signature},
};

// Deduper constants (same as proxy)
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_NUM_BITS: u64 = 637_534_199; // 76MB
const DEDUPER_RESET_CYCLE: Duration = Duration::from_secs(5 * 60);

pub struct UdpShredstreamProvider;

impl GeyserProvider for UdpShredstreamProvider {
    fn process(
        &self,
        endpoint: Endpoint,
        config: Config,
        context: ProviderContext,
    ) -> task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
        task::spawn(async move {
            let handle = task::spawn_blocking(move || {
                run_udp_shred_receiver(endpoint, config, context)
            });
            handle.await?
        })
    }
}

fn run_udp_shred_receiver(
    endpoint: Endpoint,
    config: Config,
    context: ProviderContext,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ProviderContext {
        shutdown_tx,
        mut shutdown_rx,
        start_wallclock_secs,
        start_instant,
        comparator,
        signature_tx,
        shared_counter,
        shared_shutdown,
        target_transactions,
        total_producers,
        progress,
    } = context;

    let account_pubkey: Pubkey = config.account.parse()?;
    let endpoint_name = endpoint.name.clone();

    // Parse bind address from endpoint.url (format: "0.0.0.0:20000")
    let bind_addr: SocketAddr = endpoint.url.parse()
        .map_err(|e| format!("Failed to parse UDP bind address '{}': {}", endpoint.url, e))?;

    info!(endpoint = %endpoint_name, url = %bind_addr, "Connecting");

    let exit = Arc::new(AtomicBool::new(false));
    let num_threads = std::thread::available_parallelism()
        .map(|p| usize::from(p).min(4))
        .unwrap_or(2);

    // Bind UDP sockets with SO_REUSEPORT for multi-threaded reception
    let (_port, sockets) = solana_net_utils::multi_bind_in_range_with_config(
        bind_addr.ip(),
        (bind_addr.port(), bind_addr.port() + 1),
        solana_net_utils::SocketConfig::default().reuseport(true),
        num_threads,
    )
    .map_err(|e| format!("Failed to bind UDP sockets on {}: {}", bind_addr, e))?;

    // Increase receive buffer to 256KB per socket to handle burst shred arrivals
    for socket in &sockets {
        let sock_ref = socket2::SockRef::from(socket);
        if let Err(e) = sock_ref.set_recv_buffer_size(256 * 1024) {
            warn!(endpoint = %endpoint_name, error = %e, "Failed to set SO_RCVBUF to 256KB");
        }
    }

    info!(endpoint = %endpoint_name, sockets = sockets.len(), port = bind_addr.port(), "Connected");

    let recycler: PacketBatchRecycler = Recycler::warmed(100, 1024);
    let forward_stats = Arc::new(StreamerReceiveStats::new("udp_shred_receiver"));

    // Single channel: all streamer receivers → reconstruction thread (no forwarder threads)
    let (packet_tx, packet_rx) = crossbeam_channel::bounded(2048);

    // Start streamer receiver threads (one per socket, all share the same sender)
    let mut thread_handles = Vec::new();
    for (i, socket) in sockets.into_iter().enumerate() {
        let listen_thread = streamer::receiver(
            format!("udpShred{i}"),
            Arc::new(socket),
            exit.clone(),
            packet_tx.clone(),
            recycler.clone(),
            forward_stats.clone(),
            Duration::default(),
            false,
            None,
            false,
        );
        thread_handles.push(listen_thread);
    }
    drop(packet_tx); // drop sender so reconstruction thread can detect disconnection

    // Unified dedup + reconstruction thread: eliminates per-socket forwarder threads
    // Single deduper sees ALL packets → better dedup quality, no RwLock overhead
    let metrics = Arc::new(DeshredMetrics::default());
    let exit_clone = exit.clone();
    let endpoint_name_recon = endpoint_name.clone();

    let reconstruct_thread = std::thread::Builder::new()
        .name("udpShredRecon".to_string())
        .spawn(move || {
            // Inline deduper — no RwLock needed since single-threaded
            let mut deduper = Deduper::<2, [u8]>::new(
                &mut rand::thread_rng(),
                DEDUPER_NUM_BITS,
            );
            let mut rng = rand::thread_rng();
            let mut last_dedup_reset = std::time::Instant::now();

            let mut all_shreds = ahash::HashMap::<
                Slot,
                (
                    ahash::HashMap<u32, HashSet<ComparableShred>>,
                    ShredsStateTracker,
                ),
            >::default();
            let mut slot_fec_indexes_to_iterate = Vec::<(Slot, u32)>::new();
            let mut deshredded_entries = Vec::<(Slot, Vec<solana_entry::entry::Entry>)>::new();
            let mut highest_slot_seen: Slot = 0;
            let rs_cache = ReedSolomonCache::default();

            let mut accumulator = TransactionAccumulator::new();
            let mut transaction_count = 0usize;
            let mut next_log_time = std::time::Instant::now() + Duration::from_secs(30);

            while !exit_clone.load(Ordering::Relaxed) {
                match packet_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(mut pkt_batch) => {
                        // Inline dedup — eliminates channel hop + RwLock from forwarder threads
                        solana_perf::deduper::dedup_packets_and_count_discards(
                            &deduper,
                            std::slice::from_mut(&mut pkt_batch),
                        );

                        // Periodic dedup reset
                        if last_dedup_reset.elapsed() >= Duration::from_secs(2) {
                            deduper.maybe_reset(
                                &mut rng,
                                DEDUPER_FALSE_POSITIVE_RATE,
                                DEDUPER_RESET_CYCLE,
                            );
                            last_dedup_reset = std::time::Instant::now();
                        }

                        deshred::reconstruct_shreds(
                            pkt_batch,
                            &mut all_shreds,
                            &mut slot_fec_indexes_to_iterate,
                            &mut deshredded_entries,
                            &mut highest_slot_seen,
                            &rs_cache,
                            &metrics,
                        );

                        for (_slot, entries) in deshredded_entries.drain(..) {
                            for entry in entries {
                                for tx in entry.transactions {
                                    let has_account = tx
                                        .message
                                        .static_account_keys()
                                        .iter()
                                        .any(|key| key == &account_pubkey);

                                    if !has_account {
                                        continue;
                                    }

                                    let wallclock = get_current_timestamp();
                                    let elapsed = start_instant.elapsed();
                                    let signature = tx.signatures[0].to_string();

                                    let tx_data = TransactionData {
                                        wallclock_secs: wallclock,
                                        elapsed_since_start: elapsed,
                                        start_wallclock_secs,
                                    };

                                    let updated = accumulator.record(
                                        signature.clone(),
                                        tx_data.clone(),
                                    );

                                    if updated {
                                        if let Some(envelope) = build_signature_envelope(
                                            &comparator,
                                            &endpoint_name_recon,
                                            &signature,
                                            tx_data,
                                            total_producers,
                                        ) {
                                            if let Some(target) = target_transactions {
                                                let shared = shared_counter
                                                    .fetch_add(1, Ordering::AcqRel)
                                                    + 1;
                                                if let Some(tracker) = progress.as_ref() {
                                                    tracker.record(shared);
                                                }
                                                if shared >= target
                                                    && !shared_shutdown.swap(true, Ordering::AcqRel)
                                                {
                                                    info!(
                                                        endpoint = %endpoint_name_recon,
                                                        target,
                                                        "Reached shared signature target; broadcasting shutdown"
                                                    );
                                                    let _ = shutdown_tx.send(());
                                                }
                                            }

                                            if let Some(sender) = signature_tx.as_ref() {
                                                enqueue_signature(sender, &endpoint_name_recon, &signature, envelope);
                                            }
                                        }
                                    }

                                    transaction_count += 1;
                                }
                            }
                        }

                        // Periodic stats logging
                        if std::time::Instant::now() >= next_log_time {
                            let recovered = metrics.recovered_count.load(Ordering::Relaxed);
                            let entries = metrics.entry_count.load(Ordering::Relaxed);
                            let txns = metrics.txn_count.load(Ordering::Relaxed);
                            info!(
                                endpoint = %endpoint_name_recon,
                                recovered,
                                entries,
                                txns,
                                matched = transaction_count,
                                unique = accumulator.len(),
                                "UDP shreds stats"
                            );
                            next_log_time = std::time::Instant::now() + Duration::from_secs(30);
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }

            // Flush accumulated signatures to comparator
            let unique_signatures = accumulator.len();
            let collected = accumulator.into_inner();
            comparator.add_batch(&endpoint_name_recon, collected);
            info!(
                endpoint = %endpoint_name_recon,
                total_transactions = transaction_count,
                unique_signatures,
                "Reconstruction thread exiting"
            );
        })?;
    thread_handles.push(reconstruct_thread);

    // Wait for shutdown signal
    loop {
        match shutdown_rx.try_recv() {
            Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                info!(endpoint = %endpoint_name, "Received shutdown signal");
                break;
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                info!(endpoint = %endpoint_name, "Shutdown signal lagged");
                break;
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
        }
        if exit.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Signal all threads to exit
    exit.store(true, Ordering::Relaxed);

    // Wait for threads to finish
    for handle in thread_handles {
        let _ = handle.join();
    }

    info!(endpoint = %endpoint_name, "UDP shred receiver stopped");
    Ok(())
}
