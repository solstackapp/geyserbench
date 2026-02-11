#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub use {
    bs58,
    bytes::Bytes,
    futures_util::stream::StreamExt,
    serde::{Deserialize, Serialize},
    std::{
        env,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
    tokio::{signal::ctrl_c, sync::broadcast, task},
};

mod analysis;
mod backend;
mod config;
mod deshred;
mod proto;
mod providers;
mod utils;

use anyhow::{Result, anyhow};
use backend::{BackendStatus, StreamOptions};
use crossbeam_queue::ArrayQueue;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use utils::{Comparator, ProgressTracker, get_current_timestamp};
const DEFAULT_CONFIG_PATH: &str = "config.toml";
const DEFAULT_BACKEND_STREAM_URL: &str = "wss://gb.solstack.app/v1/benchmarks/stream";
const MAX_STREAM_TRANSACTIONS: i32 = 100_000;
const SIGNATURE_QUEUE_CAPACITY: usize = 1_024;

struct CliArgs {
    config_path: Option<String>,
    disable_streaming: bool,
}

impl CliArgs {
    fn parse() -> Self {
        let mut args = env::args().skip(1);
        let mut parsed = CliArgs {
            config_path: None,
            disable_streaming: false,
        };

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" => {
                    let value = args.next().unwrap_or_else(|| {
                        eprintln!("Missing value for --config");
                        print_usage();
                        std::process::exit(1);
                    });
                    parsed.config_path = Some(value);
                }
                "--private" => {
                    parsed.disable_streaming = true;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    print_usage();
                    std::process::exit(1);
                }
            }
        }

        parsed
    }
}

fn print_usage() {
    eprintln!("Usage: geyserbench [--config <PATH>] [--private]");
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|err| anyhow!(err))?;

    let cli = CliArgs::parse();
    let config_path = cli.config_path.as_deref().unwrap_or(DEFAULT_CONFIG_PATH);
    let config = config::ConfigToml::load_or_create(config_path)?;
    info!(config_path = config_path, "Loaded configuration");

    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let start_time_local = get_current_timestamp();
    let comparator = Arc::new(Comparator::new());
    let start_instant = Instant::now();
    let clock_offset_ms: f64;
    let server_started_at_unix_ms: Option<i64>;
    let shared_counter = Arc::new(AtomicUsize::new(0));
    let shared_shutdown = Arc::new(AtomicBool::new(false));
    let aborted = Arc::new(AtomicBool::new(false));

    let high_transaction_volume = config.config.transactions > MAX_STREAM_TRANSACTIONS;
    if high_transaction_volume {
        warn!(
            transactions = config.config.transactions,
            threshold = MAX_STREAM_TRANSACTIONS,
            "Disabling backend streaming for high-volume run; backend streaming is unavailable when transactions exceed the threshold"
        );
    }

    let mut backend_settings = config.backend.clone();
    backend_settings.enabled = !(cli.disable_streaming || high_transaction_volume);
    backend_settings.url = Some(DEFAULT_BACKEND_STREAM_URL.to_string());

    let mut backend_handle = None;
    let mut signature_queues: Option<Vec<Arc<ArrayQueue<backend::SignatureEnvelope>>>> = None;
    let mut signature_forwarder: Option<thread::JoinHandle<()>> = None;
    let mut forwarder_stop: Option<Arc<AtomicBool>> = None;
    let mut backend_run_id = None;

    if backend_settings.enabled {
        let url = backend_settings
            .url
            .clone()
            .ok_or_else(|| anyhow!("backend streaming enabled but no URL configured"))?;
        let options = StreamOptions { url, summary: None };
        let handle = backend::connect_stream(options, &config.config, &config.endpoint).await?;
        clock_offset_ms = handle.clock_offset_ms();
        server_started_at_unix_ms = handle.server_started_at_unix_ms();
        let run_id = handle.run_id().to_string();
        info!(
            run_id = %run_id,
            started_at_unix_ms = server_started_at_unix_ms,
            clock_offset_ms,
            "Streaming backend session initialised"
        );
        backend_run_id = Some(run_id.clone());

        let mut queues = Vec::with_capacity(config.endpoint.len());
        for _ in 0..config.endpoint.len() {
            queues.push(Arc::new(ArrayQueue::new(SIGNATURE_QUEUE_CAPACITY)));
        }
        let queue_handles = queues.iter().map(Arc::clone).collect::<Vec<_>>();
        signature_queues = Some(queues);

        let mut status_rx = handle.status();
        let shutdown_for_backend = shutdown_tx.clone();
        let run_id_for_status = run_id.clone();
        tokio::spawn(async move {
            while status_rx.changed().await.is_ok() {
                match status_rx.borrow().clone() {
                    BackendStatus::Failed { message } => {
                        error!(run_id = %run_id_for_status, error = %message, "Backend streaming failed");
                        let _ = shutdown_for_backend.send(());
                        break;
                    }
                    BackendStatus::Completed { .. } => break,
                    BackendStatus::Ready { run_id } => {
                        debug!(run_id = %run_id, "Backend stream ready");
                    }
                    BackendStatus::Initializing => {}
                }
            }
        });

        let backend_sender = handle.signature_sender();
        let run_id_for_forwarder = run_id.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        forwarder_stop = Some(stop_flag.clone());
        let forwarder = thread::spawn(move || {
            let queue_handles = queue_handles;
            loop {
                let mut did_work = false;
                for queue in &queue_handles {
                    while let Some(envelope) = queue.pop() {
                        did_work = true;
                        if backend_sender.blocking_send(envelope).is_err() {
                            warn!(run_id = %run_id_for_forwarder, "Failed to forward signature to backend");
                            return;
                        }
                    }
                }

                let should_stop = stop_flag.load(Ordering::Acquire);
                if should_stop && queue_handles.iter().all(|queue| queue.is_empty()) {
                    break;
                }

                if !did_work {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });
        signature_forwarder = Some(forwarder);
        backend_handle = Some(handle);
    } else {
        info!("Backend streaming disabled; collecting metrics locally");
    }

    let mut handles = Vec::new();
    let endpoint_names: Vec<String> = config.endpoint.iter().map(|e| e.name.clone()).collect();
    let global_target = if config.config.transactions > 0 {
        Some(config.config.transactions as usize)
    } else {
        None
    };
    let progress_tracker = global_target.map(|target| Arc::new(ProgressTracker::new(target)));

    let total_producers = config.endpoint.len();
    for (index, endpoint) in config.endpoint.clone().into_iter().enumerate() {
        let provider = providers::create_provider(&endpoint.kind);
        let shared_config = config.config.clone();
        let signature_queue = signature_queues
            .as_ref()
            .and_then(|queues| queues.get(index).cloned());
        let context = providers::ProviderContext {
            shutdown_tx: shutdown_tx.clone(),
            shutdown_rx: shutdown_tx.subscribe(),
            start_wallclock_secs: start_time_local,
            start_instant,
            comparator: comparator.clone(),
            signature_tx: signature_queue,
            shared_counter: shared_counter.clone(),
            shared_shutdown: shared_shutdown.clone(),
            target_transactions: global_target,
            total_producers,
            progress: progress_tracker.clone(),
        };

        handles.push(provider.process(endpoint, shared_config, context));
    }

    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        let shared_shutdown = shared_shutdown.clone();
        let aborted = aborted.clone();
        async move {
            match ctrl_c().await {
                Ok(()) => {
                    let already_aborting = aborted.swap(true, Ordering::AcqRel);
                    if already_aborting {
                        info!("Received additional Ctrl+C; shutdown already in progress");
                    } else {
                        info!("Received Ctrl+C; initiating shutdown");
                    }
                    shared_shutdown.store(true, Ordering::Release);
                    let _ = shutdown_tx.send(());
                }
                Err(err) => error!(error = %err, "Failed to listen for Ctrl+C"),
            }
        }
    });

    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => error!(error = ?e, "Provider task returned error"),
            Err(e) => error!(error = ?e, "Provider join error"),
        }
    }

    let run_aborted = aborted.load(Ordering::Acquire);

    let run_summary = if !run_aborted {
        Some(analysis::compute_run_summary(
            comparator.as_ref(),
            &endpoint_names,
        ))
    } else {
        None
    };

    // Drain the forwarder before backend finalization so all queued signatures are sent
    let _ = signature_queues.take();
    if let Some(stop) = forwarder_stop.as_ref() {
        stop.store(true, Ordering::Release);
    }
    if let Some(join) = signature_forwarder.take()
        && let Err(err) = join.join()
    {
        warn!(
            "Signature forwarder thread terminated unexpectedly: {:?}",
            err
        );
    }

    let signatures_collected = shared_counter.load(Ordering::Acquire);

    if let Some(handle) = backend_handle {
        if run_aborted {
            if let Some(run_id) = backend_run_id.as_ref() {
                info!(run_id = %run_id, "Skipping backend finalisation due to user abort");
            } else {
                info!("Skipping backend finalisation due to user abort");
            }
            // Dropping the handle without calling finish() prevents the backend run from being saved.
        } else if signatures_collected == 0 {
            let run_id = backend_run_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            warn!(
                run_id = %run_id,
                "Skipping backend finalisation: no signatures were forwarded (all endpoints must observe the same transaction)"
            );
        } else {
            let run_id = backend_run_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            info!(run_id = %run_id, signatures = signatures_collected, "Finalising backend stream");
            match handle.finish().await {
                Ok(result) => {
                    info!(run_id = %run_id, "Backend completed run");
                    debug!(run_id = %run_id, response = %result.response, "Backend completion payload");
                }
                Err(err) => {
                    error!(run_id = %run_id, error = %err, "Backend streaming ended with error");
                }
            }
        }
    }

    if !run_aborted {
        if let Some(summary) = run_summary.as_ref() {
            analysis::display_run_summary(summary);
            let metrics_json = analysis::build_metrics_report(summary);
            debug!(metrics = %metrics_json, "Computed run metrics");
        }

        if let Some(run_id) = backend_run_id {
            println!("🔗 Share this benchmark run: https://runs.solstack.app/run/{run_id}");
        }
    } else {
        info!("Benchmark aborted before completion; no results were generated");
    }

    Ok(())
}
