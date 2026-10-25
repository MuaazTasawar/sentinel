use std::sync::Arc;

use sentinel_anomaly::AnomalyDetector;
use sentinel_audit::AuditChain;
use sentinel_consensus::RaftHandle;
use sentinel_crypto::SecretBytes;
use sentinel_storage::Storage;
use tokio::sync::Mutex;

use crate::handlers::unseal::UnsealState;

/// Everything a request handler needs. Cloning this is cheap: every
/// field is already an `Arc` or a handle backed by a channel, so
/// `AppState` itself derives `Clone` the way Axum's `State` extractor
/// expects, without cloning any actual data.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub raft: RaftHandle,
    pub audit: Arc<Mutex<AuditChain>>,
    /// `None` while sealed. Populated by `POST /sys/unseal` once a quorum
    /// of key-holder shares reconstructs a key that matches the vault's
    /// stored canary; cleared by `POST /sys/seal` or by an auto-seal.
    pub kek: Arc<Mutex<Option<SecretBytes>>>,
    /// Tracks the rate of secret-read access on this node. A single
    /// shared detector across all callers is deliberate: the anomaly
    /// signal is "how much total read traffic is this node seeing right
    /// now," not "how much traffic is any one client generating". A
    /// coordinated attack from multiple identities should still show up
    /// as one spike in the aggregate rate. Per-identity rate limiting is
    /// a different, complementary control this doesn't attempt to be.
    pub anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    /// The in-progress unseal quorum (shares collected so far).
    pub unseal: UnsealState,
}

/// Shared fixtures for handler and router tests, so every test module
/// builds `AppState` the same way (and adding a field means touching one
/// place, not four).
#[cfg(test)]
pub mod test_support {
    use super::*;
    use sentinel_storage::SledStorage;

    pub struct NoopTransport;

    #[async_trait::async_trait]
    impl sentinel_consensus::Transport for NoopTransport {
        async fn send_request_vote(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::RequestVoteRequest,
        ) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
            unreachable!("single-node test cluster has no peers")
        }
        async fn send_append_entries(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::AppendEntriesRequest,
        ) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
            unreachable!("single-node test cluster has no peers")
        }
    }

    pub fn default_detector() -> AnomalyDetector {
        AnomalyDetector::new(std::time::Duration::from_secs(3600), 20, 3.0)
    }

    /// Builds a single-node `AppState` in a fresh temp dir. `kek` is the
    /// initial key (`None` = sealed). Unseal threshold is 2 (a 2-of-3 test
    /// quorum) unless `unseal` overrides it.
    pub async fn state_with(
        kek: Option<SecretBytes>,
        detector: AnomalyDetector,
        unseal: UnsealState,
    ) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let raft = sentinel_consensus::spawn_raft_actor(
            1,
            vec![],
            Arc::new(NoopTransport),
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let state = AppState {
            storage,
            raft,
            audit: Arc::new(Mutex::new(AuditChain::new())),
            kek: Arc::new(Mutex::new(kek)),
            anomaly_detector: Arc::new(Mutex::new(detector)),
            unseal,
        };
        (state, dir)
    }

    pub async fn unsealed_state() -> (AppState, tempfile::TempDir) {
        let kek = SecretBytes::new(vec![0x42u8; sentinel_crypto::envelope::KEY_LEN]);
        state_with(Some(kek), default_detector(), UnsealState::new(2)).await
    }

    pub async fn sealed_state() -> (AppState, tempfile::TempDir) {
        state_with(None, default_detector(), UnsealState::new(2)).await
    }
}