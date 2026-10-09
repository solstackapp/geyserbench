use crate::{
    config::{Config, Endpoint},
    utils::get_current_timestamp,
};
use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use tokio::{
    net::lookup_host,
    sync::{mpsc, watch},
};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, error, info, warn};
use url::Url;

const STREAM_PATH: &str = "/v1/benchmarks/stream";
const COMMAND_BUFFER: usize = 256;

#[derive(Debug, Clone)]
pub struct StreamOptions {
    pub url: String,
    pub summary: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct SignatureObservation {
    pub endpoint: String,
    pub timestamp: f64,
    pub backfilled: bool,
}

#[derive(Debug, Clone)]
pub struct SignatureEnvelope {
    pub signature: String,
    pub observations: Vec<SignatureObservation>,
}

#[derive(Debug, Clone)]
pub enum BackendStatus {
    Initializing,
    Ready { run_id: String },
    Completed { response: Value },
    Failed { message: String },
}

pub struct BackendHandle {
    command_tx: mpsc::Sender<BackendCommand>,
    status_rx: watch::Receiver<BackendStatus>,
    run_id: String,
    clock_offset_ms: f64,
    server_started_at_unix_ms: Option<i64>,
}

#[derive(Clone)]
pub struct SignatureSender {
    inner: mpsc::Sender<BackendCommand>,
}

pub struct BackendCompletion {
    pub response: Value,
}

enum BackendCommand {
    Signature(SignatureEnvelope),
    End,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutboundMessage {
    Start {
        config: BackendConfigPayload,
        endpoints: Vec<BackendEndpointPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<Value>,
    },
    Signature {
        signature: String,
        observations: Vec<SignedObservationPayload>,
    },
    End,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InboundMessage {
    StartAck {
        run_id: String,
        session_nonce: String,
        #[serde(default)]
        started_at_unix_ms: Option<i64>,
    },
    Completed {
        data: Value,
    },
    Error {
        message: String,
        #[serde(default)]
        run_id: Option<String>,
    },
    #[serde(other)]
    Other,
}

struct StartAckDetails {
    run_id: String,
    session_nonce: [u8; 32],
    started_at_unix_ms: Option<i64>,
    clock_offset_ms: f64,
}

#[derive(Serialize)]
struct BackendConfigPayload {
    transactions: u32,
    account: String,
    commitment: String,
}

#[derive(Serialize)]
struct BackendEndpointPayload {
    name: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_ip: Option<String>,
}

#[derive(Serialize)]
struct SignedObservationPayload {
    endpoint: String,
    timestamp: f64,
    proof: String,
    #[serde(skip_serializing_if = "core::ops::Not::not", default)]
    backfilled: bool,
}

pub async fn connect_stream(
    options: StreamOptions,
    run_config: &Config,
    endpoints: &[Endpoint],
) -> Result<BackendHandle> {
    let url = normalize_stream_url(&options.url)?;
    let (mut socket, _) = connect_async(url.as_str())
        .await
        .map_err(|err| anyhow!("websocket connection failed: {}", err))?;

    let (status_tx, status_rx) = watch::channel(BackendStatus::Initializing);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_BUFFER);

    let endpoint_payloads = build_endpoint_payloads(endpoints).await;

    let start_message = OutboundMessage::Start {
        config: BackendConfigPayload::from_config(run_config),
        endpoints: endpoint_payloads,
        summary: options.summary.clone(),
    };

    let start_json =
        serde_json::to_string(&start_message).context("failed to serialise start message")?;
    let t_send_ms = get_current_timestamp() * 1_000.0;
    socket
        .send(Message::Text(start_json))
        .await
        .context("failed to send start message")?;

    let StartAckDetails {
        run_id,
        session_nonce,
        started_at_unix_ms,
        clock_offset_ms,
    } = wait_for_start_ack(&mut socket, t_send_ms).await?;

    info!(
        run_id = %run_id,
        started_at_unix_ms,
        clock_offset_ms,
        "Streaming backend acknowledged run"
    );
    let _ = status_tx.send(BackendStatus::Ready {
        run_id: run_id.clone(),
    });

    let (writer, reader) = socket.split();

    tokio::spawn(run_backend_loop(
        writer,
        reader,
        command_rx,
        status_tx.clone(),
        session_nonce,
        run_id.clone(),
    ));

    Ok(BackendHandle {
        command_tx,
        status_rx,
        run_id,
        clock_offset_ms,
        server_started_at_unix_ms: started_at_unix_ms,
    })
}

impl BackendHandle {
    pub fn signature_sender(&self) -> SignatureSender {
        SignatureSender {
            inner: self.command_tx.clone(),
        }
    }

    pub fn status(&self) -> watch::Receiver<BackendStatus> {
        self.status_rx.clone()
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn clock_offset_ms(&self) -> f64 {
        self.clock_offset_ms
    }

    pub fn server_started_at_unix_ms(&self) -> Option<i64> {
        self.server_started_at_unix_ms
    }

    pub async fn finish(mut self) -> Result<BackendCompletion> {
        self.command_tx
            .send(BackendCommand::End)
            .await
            .map_err(|err| anyhow!("failed to send end command: {}", err))?;

        loop {
            self.status_rx
                .changed()
                .await
                .context("backend status channel closed unexpectedly")?;
            match self.status_rx.borrow().clone() {
                BackendStatus::Completed { response } => return Ok(BackendCompletion { response }),
                BackendStatus::Failed { message } => bail!(message),
                BackendStatus::Ready { .. } | BackendStatus::Initializing => continue,
            }
        }
    }
}

impl SignatureSender {
    pub fn blocking_send(&self, envelope: SignatureEnvelope) -> Result<(), ()> {
        self.inner
            .blocking_send(BackendCommand::Signature(envelope))
            .map_err(|_| ())
    }
}

fn normalize_stream_url(raw: &str) -> Result<Url> {
    let mut parsed = if raw.starts_with("ws://")
        || raw.starts_with("wss://")
        || raw.starts_with("http://")
        || raw.starts_with("https://")
    {
        Url::parse(raw).with_context(|| format!("invalid backend url {}", raw))?
    } else {
        Url::parse(&format!("ws://{}", raw))
            .with_context(|| format!("invalid backend url {}", raw))?
    };

    match parsed.scheme() {
        "ws" | "wss" => {}
        "http" => {
            parsed
                .set_scheme("ws")
                .map_err(|_| anyhow!("failed to convert http url to websocket"))?;
        }
        "https" => {
            parsed
                .set_scheme("wss")
                .map_err(|_| anyhow!("failed to convert https url to websocket"))?;
        }
        other => bail!("unsupported backend url scheme '{}'", other),
    }

    if parsed.path() == "/" || parsed.path().is_empty() {
        parsed.set_path(STREAM_PATH);
    }

    Ok(parsed)
}

async fn wait_for_start_ack(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    t_send_ms: f64,
) -> Result<StartAckDetails> {
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(raw)) => match serde_json::from_str::<InboundMessage>(&raw) {
                Ok(InboundMessage::StartAck {
                    run_id,
                    session_nonce,
                    started_at_unix_ms,
                }) => {
                    let t_recv_ms = get_current_timestamp() * 1_000.0;
                    let bytes = hex::decode(session_nonce.trim())
                        .context("invalid session nonce received from backend")?;
                    if bytes.len() != 32 {
                        bail!("backend returned malformed session nonce");
                    }
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&bytes);
                    let clock_offset_ms = started_at_unix_ms
                        .map(|server_ms| server_ms as f64 - ((t_send_ms + t_recv_ms) / 2.0))
                        .unwrap_or(0.0);
                    debug!(
                        run_id = %run_id,
                        t_send_ms,
                        t_recv_ms,
                        server_started_at_unix_ms = started_at_unix_ms,
                        clock_offset_ms,
                        "Computed backend clock offset"
                    );
                    return Ok(StartAckDetails {
                        run_id,
                        session_nonce: array,
                        started_at_unix_ms,
                        clock_offset_ms,
                    });
                }
                Ok(InboundMessage::Error { message, run_id }) => {
                    let identifier = run_id.unwrap_or_else(|| "unknown".to_string());
                    bail!("backend rejected stream {}: {}", identifier, message);
                }
                Ok(InboundMessage::Completed { data }) => {
                    warn!(?data, "Received completion before handshake finished");
                }
                Ok(InboundMessage::Other) => {
                    debug!(payload = %raw, "Ignoring non-ack message during handshake");
                }
                Err(err) => {
                    warn!(payload = %raw, error = %err, "Failed to parse backend message during handshake");
                }
            },
            Ok(Message::Ping(payload)) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("failed to respond to backend ping during handshake")?;
            }
            Ok(Message::Close(frame)) => {
                bail!(
                    "backend closed stream during handshake: {:?}",
                    frame.map(|f| f.reason)
                );
            }
            Ok(Message::Binary(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Err(err) => bail!("backend socket failed during handshake: {}", err),
        }
    }

    Err(anyhow!(
        "backend closed connection before start acknowledgement"
    ))
}

async fn run_backend_loop(
    mut writer: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    mut reader: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    mut command_rx: mpsc::Receiver<BackendCommand>,
    status_tx: watch::Sender<BackendStatus>,
    session_nonce: [u8; 32],
    run_id: String,
) {
    let mut awaiting_completion = false;

    loop {
        tokio::select! {
            maybe_command = command_rx.recv(), if !awaiting_completion => {
                match maybe_command {
                    Some(BackendCommand::Signature(batch)) => {
                        if let Err(err) = send_signature(&mut writer, &session_nonce, batch).await {
                            error!(run_id = %run_id, error = %err, "Failed to send signature frame");
                            let _ = status_tx.send(BackendStatus::Failed { message: format!("failed to send signature: {}", err) });
                            break;
                        }
                    }
                    Some(BackendCommand::End) => {
                        match serde_json::to_string(&OutboundMessage::End) {
                            Ok(payload) => {
                                if let Err(err) = writer.send(Message::Text(payload)).await {
                                    error!(run_id = %run_id, error = %err, "Failed to send end frame");
                                    let _ = status_tx.send(BackendStatus::Failed { message: format!("failed to send end frame: {}", err) });
                                    break;
                                }
                            }
                            Err(err) => {
                                error!(run_id = %run_id, error = %err, "Failed to serialise end frame");
                                let _ = status_tx.send(BackendStatus::Failed {
                                    message: format!("failed to serialise end frame: {}", err),
                                });
                                break;
                            }
                        }
                        awaiting_completion = true;
                    }
                    None => {
                        debug!(run_id = %run_id, "Signature command channel closed before end command");
                        let _ = status_tx.send(BackendStatus::Failed {
                            message: "signature channel closed unexpectedly".to_string(),
                        });
                        break;
                    }
                }
            }
            inbound = reader.next() => {
                match inbound {
                    Some(Ok(Message::Text(raw))) => {
                        match serde_json::from_str::<InboundMessage>(&raw) {
                            Ok(InboundMessage::Completed { data }) => {
                                let _ = status_tx.send(BackendStatus::Completed { response: data });
                                if let Err(err) = writer.send(Message::Close(None)).await {
                                    debug!(run_id = %run_id, error = %err, "Failed to send websocket close frame");
                                }
                                break;
                            }
                            Ok(InboundMessage::Error { message, run_id: err_run }) => {
                                let identifier = err_run.unwrap_or_else(|| run_id.clone());
                                error!(run_id = %identifier, error = %message, "Backend reported error");
                                let _ = status_tx.send(BackendStatus::Failed { message });
                                break;
                            }
                            Ok(InboundMessage::StartAck { .. }) => {
                                debug!(run_id = %run_id, "Received duplicate start_ack message; ignoring");
                            }
                            Ok(InboundMessage::Other) => {
                                debug!(run_id = %run_id, payload = %raw, "Ignoring backend message");
                            }
                            Err(err) => {
                                warn!(run_id = %run_id, payload = %raw, error = %err, "Failed to parse backend message");
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if let Err(err) = writer.send(Message::Pong(payload)).await {
                            warn!(run_id = %run_id, error = %err, "Failed to respond to backend ping");
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let reason = frame.map(|f| f.reason).unwrap_or_default();
                        warn!(run_id = %run_id, reason = %reason, "Backend closed websocket");
                        let _ = status_tx.send(BackendStatus::Failed {
                            message: format!("backend closed connection: {}", reason),
                        });
                        break;
                    }
                    Some(Ok(Message::Binary(_)))
                    | Some(Ok(Message::Pong(_)))
                    | Some(Ok(Message::Frame(_))) => {}
                    Some(Err(err)) => {
                        error!(run_id = %run_id, error = %err, "Backend websocket error");
                        let _ = status_tx.send(BackendStatus::Failed {
                            message: format!("backend websocket error: {}", err),
                        });
                        break;
                    }
                    None => {
                        if awaiting_completion {
                            warn!(run_id = %run_id, "Backend closed stream before completion frame");
                        }
                        let _ = status_tx.send(BackendStatus::Failed {
                            message: "backend websocket closed unexpectedly".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
}

async fn send_signature(
    writer: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    session_nonce: &[u8; 32],
    batch: SignatureEnvelope,
) -> Result<()> {
    let observations = batch
        .observations
        .into_iter()
        .map(|obs| SignedObservationPayload {
            endpoint: obs.endpoint.clone(),
            timestamp: obs.timestamp,
            proof: compute_proof(
                session_nonce,
                &obs.endpoint,
                &batch.signature,
                obs.timestamp,
            ),
            backfilled: obs.backfilled,
        })
        .collect::<Vec<_>>();

    let payload = OutboundMessage::Signature {
        signature: batch.signature,
        observations,
    };

    let json = serde_json::to_string(&payload).context("failed to serialise signature payload")?;
    writer
        .send(Message::Text(json))
        .await
        .context("failed to send signature payload")?;
    Ok(())
}

fn compute_proof(
    session_nonce: &[u8; 32],
    endpoint: &str,
    signature: &str,
    timestamp: f64,
) -> String {
    let quantized_steps = (timestamp * 10.0).round() as i64;
    let quantized_timestamp = quantized_steps as f64 / 10.0;

    let mut hasher = Hasher::new();
    hasher.update(session_nonce);
    hasher.update(endpoint.as_bytes());
    hasher.update(signature.as_bytes());
    hasher.update(&quantized_timestamp.to_be_bytes());
    let result = hasher.finalize();
    hex::encode(result.as_bytes())
}

impl BackendConfigPayload {
    fn from_config(config: &Config) -> Self {
        Self {
            transactions: config.transactions.max(0) as u32,
            account: config.account.clone(),
            commitment: config.commitment.as_str().to_string(),
        }
    }
}

impl BackendEndpointPayload {
    fn from_endpoint(endpoint: &Endpoint, provided_ip: Option<String>) -> Self {
        let (kind_str, url) = match endpoint.kind {
            // Backend doesn't know UDP variant: map kind and wrap bare socket addr as URL
            crate::config::EndpointKind::UdpShredstream => {
                ("shredstream", format!("udp://{}", endpoint.url))
            }
            _ => (endpoint.kind.as_str(), endpoint.url.clone()),
        };
        Self {
            name: endpoint.name.clone(),
            url,
            kind: Some(kind_str.to_string()),
            resolved_ip: provided_ip,
        }
    }
}

async fn build_endpoint_payloads(endpoints: &[Endpoint]) -> Vec<BackendEndpointPayload> {
    let mut payloads = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let ip = resolve_endpoint_ip(endpoint).await;
        payloads.push(BackendEndpointPayload::from_endpoint(endpoint, ip));
    }
    payloads
}

async fn resolve_endpoint_ip(endpoint: &Endpoint) -> Option<String> {
    // UDP endpoints use bare socket addresses (e.g. "127.0.0.1:8001"), not URLs
    if matches!(endpoint.kind, crate::config::EndpointKind::UdpShredstream) {
        return endpoint.url.parse::<std::net::SocketAddr>()
            .ok()
            .map(|addr| addr.ip().to_string());
    }

    let parsed = match Url::parse(&endpoint.url) {
        Ok(url) => url,
        Err(err) => {
            warn!(endpoint = %endpoint.name, url = %endpoint.url, error = %err, "Failed to parse endpoint URL");
            return None;
        }
    };

    let host = match parsed.host_str() {
        Some(host) => host.to_string(),
        None => {
            warn!(endpoint = %endpoint.name, url = %endpoint.url, "Endpoint URL has no host component");
            return None;
        }
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    let target = format!("{}:{}", host, port);
    match lookup_host(target).await {
        Ok(mut addrs) => addrs.next().map(|addr| addr.ip().to_string()),
        Err(err) => {
            warn!(endpoint = %endpoint.name, host = %host, error = %err, "DNS lookup failed for endpoint");
            None
        }
    }
}
