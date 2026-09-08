use std::sync::Arc;

use sentinel_anomaly::AnomalyDetector;
use sentinel_audit::AuditChain;
use sentinel_consensus::RaftHandle;
use sentinel_crypto::SecretBytes;
use sentinel_storage::Storage;
use tokio::sync::Mutex;

/// Everything a request handler needs. Cloning this is cheap — every
/// field is already an `Arc` or a handle backed by a channel, so
/// `AppState` itself derives `Clone` the way Axum's `State` extractor
/// expects, without cloning any actual data.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub raft: RaftHandle,
    pub audit: Arc<Mutex<AuditChain>>,
    /// `None` while sealed. Populated once Phase 4's hardware-quorum
    /// unseal flow reconstructs the KEK and hands it to a running node
    /// (that hand-off itself isn't wired up yet — see the note on
    /// `unseal_endpoint` in `main.rs` — so for now this starts `None`
    /// and stays that way until a future phase wires the real unseal
    /// RPC in).
    pub kek: Arc<Mutex<Option<SecretBytes>>>,
    /// Tracks the rate of secret-read access on this node. A single
    /// shared detector across all callers is deliberate: the anomaly
    /// signal is "how much total read traffic is this node seeing right
    /// now," not "how much traffic is any one client generating" — a
    /// coordinated attack from multiple identities should still show up
    /// as one spike in the aggregate rate. Per-identity rate limiting is
    /// a different, complementary control this doesn't attempt to be.
    pub anomaly_detector: Arc<Mutex<AnomalyDetector>>,
}