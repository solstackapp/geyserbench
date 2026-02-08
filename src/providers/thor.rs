use std::{error::Error, sync::atomic::Ordering, time::Duration};

use crate::{
    config::{Config, Endpoint},
    utils::{TransactionData, get_current_timestamp, open_log_file, write_log_entry},
};

use futures_util::StreamExt;
use solana_pubkey::Pubkey;
use thorstreamer_grpc_client::{ClientConfig, ThorClient, parse_message};
use thorstreamer_grpc_client::proto::thor_streamer::types::message_wrapper::EventMessage;
use tokio::task;
use tracing::{Level, info};

use super::{
    GeyserProvider, ProviderContext,
    common::{
        TransactionAccumulator, build_signature_envelope, enqueue_signature, fatal_connection_error,
    },
};

pub struct ThorProvider;

impl GeyserProvider for ThorProvider {
    fn process(
        &self,
        endpoint: Endpoint,
        config: Config,
        context: ProviderContext,
    ) -> task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
        task::spawn(async move { process_thor_endpoint(endpoint, config, context).await })
    }
}

async fn process_thor_endpoint(
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
    let signature_sender = signature_tx;
    let account_pubkey = config.account.parse::<Pubkey>()?;
    let endpoint_name = endpoint.name.clone();

    let mut log_file = if tracing::enabled!(Level::TRACE) {
        Some(open_log_file(&endpoint_name)?)
    } else {
        None
    };

    let endpoint_url = endpoint.url.clone();

    info!(endpoint = %endpoint_name, url = %endpoint_url, "Connecting");

    let client_config = ClientConfig {
        server_addr: endpoint_url.clone(),
        token: endpoint.x_token.clone().unwrap_or_default(),
        timeout: Duration::from_secs(30),
    };

    let mut client = ThorClient::new(client_config)
        .await
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err));

    info!(endpoint = %endpoint_name, "Connected");

    let mut stream = client
        .subscribe_to_transactions()
        .await
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err));

    let mut accumulator = TransactionAccumulator::new();
    let mut transaction_count = 0usize;

    loop {
        tokio::select! { biased;
            _ = shutdown_rx.recv() => {
                info!(endpoint = %endpoint_name, "Received stop signal");
                break;
            }

            message = stream.next() => {
                let Some(Ok(msg)) = message else { continue };
                let Ok(message_wrapper) = parse_message(&msg.data) else { continue };
                let Some(EventMessage::Transaction(transaction_event_wrapper)) = message_wrapper.event_message else { continue };
                let Some(transaction) = transaction_event_wrapper.transaction.as_ref() else { continue };
                let Some(message) = transaction.message.as_ref() else { continue };

                // Get signature from the first signature in the transaction
                let Some(sig_bytes) = transaction.signatures.first() else { continue };

                let has_account = message
                    .account_keys
                    .iter()
                    .any(|key| key.as_slice() == account_pubkey.as_ref());

                if has_account {
                    let wallclock = get_current_timestamp();
                    let elapsed = start_instant.elapsed();
                    let signature = bs58::encode(sig_bytes).into_string();

                    if let Some(file) = log_file.as_mut() {
                        write_log_entry(file, wallclock, &endpoint_name, &signature)?;
                    }

                    let tx_data = TransactionData {
                        wallclock_secs: wallclock,
                        elapsed_since_start: elapsed,
                        start_wallclock_secs,
                    };

                    let updated = accumulator.record(
                        signature.clone(),
                        tx_data.clone(),
                    );

                    if updated
                        && let Some(envelope) = build_signature_envelope(
                            &comparator,
                            &endpoint_name,
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
                                    info!(endpoint = %endpoint_name, target, "Reached shared signature target; broadcasting shutdown");
                                    let _ = shutdown_tx.send(());
                                }
                            }

                            if let Some(sender) = signature_sender.as_ref() {
                                enqueue_signature(sender, &endpoint_name, &signature, envelope);
                            }
                        }

                    transaction_count += 1;
                }
            }
        }
    }

    let unique_signatures = accumulator.len();
    let collected = accumulator.into_inner();
    comparator.add_batch(&endpoint_name, collected);
    info!(
        endpoint = %endpoint_name,
        total_transactions = transaction_count,
        unique_signatures,
        "Stream closed after dispatching transactions"
    );

    Ok(())
}
