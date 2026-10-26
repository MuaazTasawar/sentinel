use std::sync::Arc;
use std::time::Duration;

use sentinel_anomaly::AnomalyDetector;
use sentinel_audit::AuditChain;
use sentinel_consensus::RaftHandle;
use sentinel_crypto::SecretBytes;
use sentinel_storage::Storage;
use tokio::sync::{watch, Mutex};

use crate::handlers::unseal::UnsealState;
use crate::middleware::authz::Policy;
use crate::transport::SealForwarder;

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
    /// Highest Raft log index this node's state machine has applied to
    /// storage. A write handler waits on it so a client reads its own write.
    pub applied: watch::Receiver<u64>,
    /// How long a write waits for a majority commit (and for this node to
    /// apply it) before answering 504.
    pub commit_timeout: Duration,
    /// Who may call what.
    pub policy: Arc<Policy>,
    /// How this node asks the leader to seal the cluster when it cannot do so itself.
    pub seal_forwarder: Arc<dyn SealForwarder>,
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

    /// A transport that wins every election (grants all votes) but can never
    /// replicate: the shape of a leader that has lost its majority.
    pub struct VotesButNoReplication;

    #[async_trait::async_trait]
    impl sentinel_consensus::Transport for VotesButNoReplication {
        async fn send_request_vote(
            &self,
            _peer_id: u64,
            req: sentinel_consensus::RequestVoteRequest,
        ) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
            Ok(sentinel_consensus::RequestVoteResponse { term: req.term, vote_granted: true })
        }
        async fn send_append_entries(
            &self,
            peer_id: u64,
            _req: sentinel_consensus::AppendEntriesRequest,
        ) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
            Err(sentinel_consensus::TransportError::Unreachable(peer_id))
        }
    }

    pub fn default_detector() -> AnomalyDetector {
        AnomalyDetector::new(std::time::Duration::from_secs(3600), 20, 3.0)
    }

    /// Builds a `AppState` backed by a real Raft actor and the real apply
    /// loop, in a fresh temp dir. By default it is a single-node cluster
    /// (which commits instantly) with a 5 s commit timeout.
    pub async fn build(
        kek: Option<SecretBytes>,
        detector: AnomalyDetector,
        unseal: UnsealState,
        peers: Vec<u64>,
        transport: Arc<dyn sentinel_consensus::Transport>,
        commit_timeout: Duration,
    ) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let peers_is_empty = peers.is_empty();
        let (raft, committed) = sentinel_consensus::spawn_raft_actor_with_apply(
            1,
            peers,
            transport,
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        let kek = Arc::new(Mutex::new(kek));
        let audit = Arc::new(Mutex::new(AuditChain::new()));
        let applied = crate::statemachine::spawn_apply_loop(committed, storage.clone(), kek.clone(), audit.clone());
        if peers_is_empty {
            // A single-node cluster elects itself; wait for that instead of
            // guessing how long it takes on a loaded machine.
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while raft.inspect().await.0 != sentinel_consensus::Role::Leader {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("a single-node test cluster should elect itself");
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        let state = AppState {
            storage,
            raft,
            audit,
            kek,
            anomaly_detector: Arc::new(Mutex::new(detector)),
            unseal,
            applied,
            commit_timeout,
            policy: Arc::new(Policy::allow_any()),
            seal_forwarder: Arc::new(crate::transport::NoForwarder),
        };
        (state, dir)
    }

    /// Builds a single-node `AppState`. `kek` is the initial key (`None` =
    /// sealed). Unseal threshold is 2 (a 2-of-3 test quorum) unless `unseal`
    /// overrides it.
    pub async fn state_with(
        kek: Option<SecretBytes>,
        detector: AnomalyDetector,
        unseal: UnsealState,
    ) -> (AppState, tempfile::TempDir) {
        build(kek, detector, unseal, vec![], Arc::new(NoopTransport), Duration::from_secs(5)).await
    }

    pub async fn unsealed_state() -> (AppState, tempfile::TempDir) {
        let kek = SecretBytes::new(vec![0x42u8; sentinel_crypto::envelope::KEY_LEN]);
        state_with(Some(kek), default_detector(), UnsealState::new(2)).await
    }

    pub async fn sealed_state() -> (AppState, tempfile::TempDir) {
        state_with(None, default_detector(), UnsealState::new(2)).await
    }
}