use crossbeam_queue::ArrayQueue;
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    },
    time::Instant,
};
use tokio::sync::broadcast;

use crate::{
    backend::SignatureEnvelope,
    config::{Config, Endpoint, EndpointKind},
    utils::{Comparator, ProgressTracker},
};

pub mod arpc;
pub mod common;
pub mod jetstream;
pub mod shreder;
pub mod shredstream;
pub mod thor;
pub mod udp_shredstream;
pub mod yellowstone;
mod yellowstone_client;

pub trait GeyserProvider: Send + Sync {
    fn process(
        &self,
        endpoint: Endpoint,
        config: Config,
        context: ProviderContext,
    ) -> tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>;
}

pub fn create_provider(kind: &EndpointKind) -> Box<dyn GeyserProvider> {
    match kind {
        EndpointKind::Yellowstone => Box::new(yellowstone::YellowstoneProvider),
        EndpointKind::Arpc => Box::new(arpc::ArpcProvider),
        EndpointKind::Thor => Box::new(thor::ThorProvider),
        EndpointKind::Shreder => Box::new(shreder::ShrederProvider),
        EndpointKind::Shredstream => Box::new(shredstream::ShredstreamProvider),
        EndpointKind::Jetstream => Box::new(jetstream::JetstreamProvider),
        EndpointKind::UdpShredstream => Box::new(udp_shredstream::UdpShredstreamProvider),
    }
}

pub struct ProviderContext {
    pub shutdown_tx: broadcast::Sender<()>,
    pub shutdown_rx: broadcast::Receiver<()>,
    pub start_wallclock_secs: f64,
    pub start_instant: Instant,
    pub comparator: Arc<Comparator>,
    pub signature_tx: Option<Arc<ArrayQueue<SignatureEnvelope>>>,
    pub shared_counter: Arc<AtomicUsize>,
    pub shared_shutdown: Arc<AtomicBool>,
    pub target_transactions: Option<usize>,
    pub total_producers: usize,
    pub progress: Option<Arc<ProgressTracker>>,
}
