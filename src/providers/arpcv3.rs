use std::{error::Error, sync::atomic::Ordering};

use futures::channel::mpsc::unbounded;
use futures_util::stream::StreamExt;
use solana_pubkey::Pubkey;
use tokio::task;
use tonic::{
    Request, Status,
    metadata::AsciiMetadataValue,
    transport::{Channel, ClientTlsConfig},
};
use tracing::{Level, error, info, warn};

use crate::{
    config::{Config, Endpoint},
    utils::{TransactionData, get_current_timestamp, open_log_file, write_log_entry},
};

use super::{
    GeyserProvider, ProviderContext,
    common::{
        TransactionAccumulator, build_signature_envelope, enqueue_signature, fatal_connection_error,
    },
};

#[allow(clippy::all, dead_code)]
pub mod arpc {
    include!(concat!(env!("OUT_DIR"), "/arpcv3/arpc.rs"));
}

use arpc::{
    AckReason, ClientMessage, ErrorCode, SubscriptionRequest, TransactionEncoding,
    TransactionSubscription, a_rpc_client::ARpcClient, client_message::Msg,
    server_message::Payload, subscription_request::Kind,
};

/// Client-chosen subscription id (0..63); the benchmark opens a single subscription.
const SUB_ID: u32 = 0;

pub struct ArpcV3Provider;

impl GeyserProvider for ArpcV3Provider {
    fn process(
        &self,
        endpoint: Endpoint,
        config: Config,
        context: ProviderContext,
    ) -> task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
        task::spawn(async move { process_arpcv3_endpoint(endpoint, config, context).await })
    }
}

async fn process_arpcv3_endpoint(
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
    let x_token = endpoint
        .x_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .map(AsciiMetadataValue::try_from)
        .transpose()
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err));

    info!(endpoint = %endpoint_name, url = %endpoint_url, "Connecting");

    let channel = Channel::from_shared(endpoint_url)
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err))
        .tls_config(ClientTlsConfig::new().with_native_roots())
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err))
        .connect()
        .await
        .unwrap_or_else(|err| fatal_connection_error(&endpoint_name, err));
    let mut client = ARpcClient::with_interceptor(channel, move |mut request: Request<()>| {
        if let Some(token) = x_token.clone() {
            request.metadata_mut().insert("x-token", token);
        }
        Ok::<_, Status>(request)
    });
    info!(endpoint = %endpoint_name, "Connected");

    let subscription = ClientMessage {
        msg: Some(Msg::Subscribe(SubscriptionRequest {
            sub_id: SUB_ID,
            kind: Some(Kind::Transactions(TransactionSubscription {
                account_include: vec![account_pubkey.to_bytes().to_vec()],
                account_exclude: Vec::new(),
                account_required: Vec::new(),
                // Votes stay included so vote accounts can be benchmarked too.
                exclude_votes: false,
                encoding: TransactionEncoding::Binary as i32,
            })),
        })),
    };

    // `subscribe_tx` lives until the end of this function: dropping it half-closes
    // the request stream, which ends the subscription.
    let (subscribe_tx, subscribe_rx) = unbounded::<ClientMessage>();
    subscribe_tx.unbounded_send(subscription)?;
    let mut stream = client.subscribe(subscribe_rx).await?.into_inner();

    let mut accumulator = TransactionAccumulator::new();
    let mut transaction_count = 0usize;

    loop {
        tokio::select! { biased;
            _ = shutdown_rx.recv() => {
                info!(endpoint = %endpoint_name, "Received stop signal");
                break;
            }

            message = stream.next() => {
                let msg = match message {
                    Some(Ok(msg)) => msg,
                    Some(Err(status)) => {
                        error!(endpoint = %endpoint_name, error = ?status, "Error receiving message from stream");
                        break;
                    }
                    None => {
                        info!(endpoint = %endpoint_name, "Stream closed by server");
                        break;
                    }
                };

                let tx = match msg.payload {
                    Some(Payload::BinaryTransaction(tx)) => tx,
                    Some(Payload::Ack(ack)) => {
                        if !ack.accepted {
                            let reason = AckReason::try_from(ack.reason)
                                .map_or_else(|_| ack.reason.to_string(), |r| r.as_str_name().to_owned());
                            fatal_connection_error(
                                &endpoint_name,
                                format!("subscription {} rejected: {reason}", ack.sub_id),
                            );
                        }
                        info!(endpoint = %endpoint_name, sub_id = ack.sub_id, "Subscription accepted");
                        continue;
                    }
                    Some(Payload::Error(err)) => {
                        // Termination is signalled by the stream itself ending; keep reading until then.
                        let code = ErrorCode::try_from(err.code)
                            .map_or_else(|_| err.code.to_string(), |c| c.as_str_name().to_owned());
                        error!(
                            endpoint = %endpoint_name,
                            code = %code,
                            message = %err.message,
                            retry_after_ms = err.retry_after_ms,
                            "Server reported stream error"
                        );
                        continue;
                    }
                    Some(Payload::Gap(gap)) => {
                        warn!(
                            endpoint = %endpoint_name,
                            from_seq = gap.from_seq,
                            to_seq = gap.to_seq,
                            "Server skipped messages"
                        );
                        continue;
                    }
                    _ => continue,
                };

                if tx.signature.is_empty() {
                    warn!(endpoint = %endpoint_name, slot = tx.slot, "Missing signature in transaction");
                    continue;
                }

                let wallclock = get_current_timestamp();
                let elapsed = start_instant.elapsed();
                let signature = bs58::encode(&tx.signature).into_string();

                if let Some(file) = log_file.as_mut() {
                    write_log_entry(file, wallclock, &endpoint_name, &signature)?;
                }

                let tx_data = TransactionData {
                    wallclock_secs: wallclock,
                    elapsed_since_start: elapsed,
                    start_wallclock_secs,
                };

                let updated = accumulator.record(signature.clone(), tx_data.clone());

                if updated && let Some(envelope) = build_signature_envelope(
                    &comparator,
                    &endpoint_name,
                    &signature,
                    tx_data,
                    total_producers,
                ) {
                    if let Some(target) = target_transactions {
                        let shared = shared_counter.fetch_add(1, Ordering::AcqRel) + 1;
                        if let Some(tracker) = progress.as_ref() {
                            tracker.record(shared);
                        }
                        if shared >= target && !shared_shutdown.swap(true, Ordering::AcqRel) {
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
