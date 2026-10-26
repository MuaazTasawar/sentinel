//! The replicated state machine.
//!
//! Every change to the vault's state (writing or deleting a secret, sealing)
//! is a [`Command`] that goes into the Raft log. A node changes its own
//! storage **only** when a command comes back out of the log as *committed*,
//! i.e. after a majority of the cluster has it durably. HTTP handlers never
//! write storage directly; they propose a command and wait. That is what
//! makes "the write succeeded" mean "a majority has it", and what makes every
//! node (leader or follower) end up with the same data and the same sealed
//! state.
//!
//! Commands carry already-encrypted values: the encryption happens on the
//! node that received the request, using the key-encryption key held in its
//! memory, and the log (on disk, on every node) only ever sees ciphertext.
//! Followers therefore apply writes without needing to be unsealed.
//!
//! After a restart a node replays its committed log from the start. Puts and
//! deletes are idempotent, but replaying an old `Seal` into a node that has
//! since been unsealed would wrongly re-seal it, so the loop persists the
//! index it has applied and skips everything at or below it.
//! (Operational rule that follows: never wipe the Raft directory without also
//! wiping the storage directory, or vice versa.)

use std::sync::Arc;

use bincode::Options;
use sentinel_audit::AuditChain;
use sentinel_consensus::LogEntry;
use sentinel_crypto::SecretBytes;
use sentinel_storage::{Storage, StorageError};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Mutex};

/// Where the applied-log-index checkpoint lives. Outside `secrets/`, so it is
/// never listed as a secret.
pub const APPLIED_INDEX_KEY: &str = "sys/applied-index";

const WIRE_VERSION: u8 = 1;
const MAX_COMMAND_BYTES: u64 = 8 * 1024 * 1024;

/// Storage key for a secret named `key`.
pub fn storage_key(key: &str) -> String {
    format!("secrets/{key}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// `value` is a bincode-encoded `EnvelopeCiphertext`, never plaintext.
    Put { key: String, value: Vec<u8> },
    Delete { key: String },
    /// Seal every node. `reason` is free text for the audit log.
    Seal { reason: String },
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().with_limit(MAX_COMMAND_BYTES)
}

impl Command {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        out.extend(codec().serialize(self).expect("a Command always serializes"));
        out
    }

    /// `None` for anything that is not exactly one well-formed command of a
    /// supported version (so a malformed log entry can never panic a node).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (version, rest) = bytes.split_first()?;
        if *version != WIRE_VERSION {
            return None;
        }
        codec().deserialize(rest).ok()
    }
}

/// Starts the loop that turns committed log entries into storage changes.
///
/// Returns a watch whose value is the highest log index this node has applied,
/// so a handler that just got its entry committed can wait until its own node
/// has applied it too (read-your-writes on the node that took the write).
pub fn spawn_apply_loop(
    mut committed: mpsc::UnboundedReceiver<LogEntry>,
    storage: Arc<dyn Storage>,
    kek: Arc<Mutex<Option<SecretBytes>>>,
    audit: Arc<Mutex<AuditChain>>,
) -> watch::Receiver<u64> {
    let (applied_tx, applied_rx) = watch::channel(0u64);

    tokio::spawn(async move {
        let mut applied = match load_applied_index(&*storage).await {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(error = %e, "cannot read the applied-index checkpoint; the state machine will not run");
                return;
            }
        };
        advance(&applied_tx, applied);

        while let Some(entry) = committed.recv().await {
            if entry.index <= applied {
                // Already reflected in storage (we are replaying after a restart).
                advance(&applied_tx, entry.index);
                continue;
            }
            if let Err(e) = apply_entry(&entry, &*storage, &kek, &audit).await {
                // Fail-stop: carrying on past a failed apply would let this
                // node silently diverge. Writers will see timeouts instead.
                tracing::error!(index = entry.index, error = %e, "failed to apply a committed entry; stopping the state machine");
                break;
            }
            applied = entry.index;
            if let Err(e) = storage.put(APPLIED_INDEX_KEY, applied.to_be_bytes().to_vec()).await {
                tracing::error!(error = %e, "failed to record the applied index; stopping the state machine");
                break;
            }
            advance(&applied_tx, applied);
        }
    });

    applied_rx
}

fn advance(tx: &watch::Sender<u64>, index: u64) {
    tx.send_if_modified(|current| {
        if index > *current {
            *current = index;
            true
        } else {
            false
        }
    });
}

async fn load_applied_index(storage: &dyn Storage) -> Result<u64, StorageError> {
    match storage.get(APPLIED_INDEX_KEY).await {
        Ok(bytes) => {
            let arr: [u8; 8] =
                bytes.try_into().map_err(|_| StorageError::Backend("applied-index checkpoint is not 8 bytes".into()))?;
            Ok(u64::from_be_bytes(arr))
        }
        Err(StorageError::NotFound(_)) => Ok(0),
        Err(e) => Err(e),
    }
}

async fn apply_entry(
    entry: &LogEntry,
    storage: &dyn Storage,
    kek: &Mutex<Option<SecretBytes>>,
    audit: &Mutex<AuditChain>,
) -> Result<(), StorageError> {
    match Command::decode(&entry.command) {
        None => {
            // Committed but unintelligible (corrupt, or from a newer version).
            // It still occupies its slot, so skip it visibly rather than stall.
            audit.lock().await.append(format!("ignored an undecodable committed command at log index {}", entry.index));
        }
        Some(Command::Put { key, value }) => storage.put(&storage_key(&key), value).await?,
        Some(Command::Delete { key }) => match storage.delete(&storage_key(&key)).await {
            Ok(()) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        },
        Some(Command::Seal { reason }) => {
            *kek.lock().await = None;
            audit
                .lock()
                .await
                .append(format!("vault SEALED by a committed cluster-wide seal command (log index {}): {reason}", entry.index));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_storage::SledStorage;
    use std::time::Duration;

    #[test]
    fn commands_round_trip() {
        let cmds = [
            Command::Put { key: "db".into(), value: vec![1, 2, 3] },
            Command::Delete { key: "db".into() },
            Command::Seal { reason: "anomaly".into() },
        ];
        for c in cmds {
            assert_eq!(Command::decode(&c.encode()), Some(c));
        }
    }

    #[test]
    fn malformed_commands_decode_to_none_and_never_panic() {
        assert_eq!(Command::decode(&[]), None);
        assert_eq!(Command::decode(&[99, 1, 2, 3]), None, "unknown version");
        assert_eq!(Command::decode(&[1]), None, "version byte alone");
        assert_eq!(Command::decode(b"SEAL:garbage"), None);

        let mut trailing = Command::Delete { key: "k".into() }.encode();
        trailing.push(0);
        assert_eq!(Command::decode(&trailing), None, "trailing bytes are rejected");

        // A hostile length prefix must not allocate gigabytes.
        let hostile = [1u8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert_eq!(Command::decode(&hostile), None);
    }

    struct Harness {
        tx: mpsc::UnboundedSender<LogEntry>,
        storage: Arc<dyn Storage>,
        kek: Arc<Mutex<Option<SecretBytes>>>,
        audit: Arc<Mutex<AuditChain>>,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn harness_with_applied(applied_index: Option<u64>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        if let Some(i) = applied_index {
            storage.put(APPLIED_INDEX_KEY, i.to_be_bytes().to_vec()).await.unwrap();
        }
        let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
        let audit = Arc::new(Mutex::new(AuditChain::new()));
        let (tx, rx) = mpsc::unbounded_channel();
        let applied = spawn_apply_loop(rx, storage.clone(), kek.clone(), audit.clone());
        Harness { tx, storage, kek, audit, applied, _dir: dir }
    }

    fn entry(index: u64, cmd: &Command) -> LogEntry {
        LogEntry { term: 1, index, command: cmd.encode() }
    }

    async fn wait_applied(h: &Harness, index: u64) {
        let mut rx = h.applied.clone();
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index)).await.expect("timed out").unwrap();
    }

    #[tokio::test]
    async fn committed_puts_and_deletes_change_storage_and_report_progress() {
        let h = harness_with_applied(None).await;
        h.tx.send(entry(1, &Command::Put { key: "a".into(), value: vec![9, 9] })).unwrap();
        wait_applied(&h, 1).await;
        assert_eq!(h.storage.get("secrets/a").await.unwrap(), vec![9, 9]);

        h.tx.send(entry(2, &Command::Delete { key: "a".into() })).unwrap();
        h.tx.send(entry(3, &Command::Delete { key: "never-existed".into() })).unwrap();
        wait_applied(&h, 3).await;
        assert!(h.storage.get("secrets/a").await.is_err());

        // The checkpoint is durable and lives outside the secrets namespace.
        assert_eq!(load_applied_index(&*h.storage).await.unwrap(), 3);
        assert!(h.storage.list("secrets/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_committed_seal_command_seals_the_node_and_is_audited() {
        let h = harness_with_applied(None).await;
        assert!(h.kek.lock().await.is_some());
        h.tx.send(entry(1, &Command::Seal { reason: "test anomaly".into() })).unwrap();
        wait_applied(&h, 1).await;

        assert!(h.kek.lock().await.is_none());
        let chain = h.audit.lock().await;
        assert!(chain.verify().is_ok());
        assert!(chain.entries().iter().any(|e| e.event.contains("committed cluster-wide seal command") && e.event.contains("test anomaly")));
    }

    #[tokio::test]
    async fn entries_at_or_below_the_checkpoint_are_skipped_on_replay() {
        // The node already applied up to index 5 before it restarted.
        let h = harness_with_applied(Some(5)).await;
        wait_applied(&h, 5).await;

        // Replay delivers old entries again, including an old Seal. It must NOT
        // re-seal a node that was unsealed since, nor redo the old write.
        h.tx.send(entry(3, &Command::Seal { reason: "ancient".into() })).unwrap();
        h.tx.send(entry(4, &Command::Put { key: "stale".into(), value: vec![1] })).unwrap();
        h.tx.send(entry(6, &Command::Put { key: "fresh".into(), value: vec![2] })).unwrap();
        wait_applied(&h, 6).await;

        assert!(h.kek.lock().await.is_some(), "an old seal must not be replayed");
        assert!(h.storage.get("secrets/stale").await.is_err());
        assert_eq!(h.storage.get("secrets/fresh").await.unwrap(), vec![2]);
    }

    #[tokio::test]
    async fn an_undecodable_committed_entry_is_skipped_visibly_without_stalling() {
        let h = harness_with_applied(None).await;
        h.tx.send(LogEntry { term: 1, index: 1, command: b"not a command".to_vec() }).unwrap();
        h.tx.send(entry(2, &Command::Put { key: "after".into(), value: vec![5] })).unwrap();
        wait_applied(&h, 2).await;

        assert_eq!(h.storage.get("secrets/after").await.unwrap(), vec![5]);
        assert!(h.audit.lock().await.entries().iter().any(|e| e.event.contains("undecodable committed command at log index 1")));
    }

    // ---- three real nodes ----

    use sentinel_consensus::{
        spawn_raft_actor_with_apply, AppendEntriesRequest, AppendEntriesResponse, ElectionTimeoutRange, RaftHandle,
        RequestVoteRequest, RequestVoteResponse, Role, Transport, TransportError,
    };
    use std::collections::HashMap;

    struct Loopback {
        handles: Mutex<HashMap<u64, RaftHandle>>,
    }
    struct LoopTransport(Arc<Loopback>);

    impl LoopTransport {
        async fn peer(&self, id: u64) -> Result<RaftHandle, TransportError> {
            self.0.handles.lock().await.get(&id).cloned().ok_or(TransportError::Unreachable(id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for LoopTransport {
        async fn send_request_vote(&self, p: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.peer(p).await?.request_vote(req).await)
        }
        async fn send_append_entries(&self, p: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.peer(p).await?.append_entries(req).await)
        }
    }

    struct Node {
        raft: RaftHandle,
        storage: Arc<dyn Storage>,
        kek: Arc<Mutex<Option<SecretBytes>>>,
        audit: Arc<Mutex<AuditChain>>,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn three_nodes() -> HashMap<u64, Node> {
        let ids = [1u64, 2, 3];
        let net = Arc::new(Loopback { handles: Mutex::new(HashMap::new()) });
        let mut nodes = HashMap::new();
        for &id in &ids {
            let dir = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
            let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
            let audit = Arc::new(Mutex::new(AuditChain::new()));
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let (raft, rx) = spawn_raft_actor_with_apply(
                id,
                peers,
                Arc::new(LoopTransport(net.clone())),
                Duration::from_millis(20),
                ElectionTimeoutRange { min_ms: 80, max_ms: 150 },
            );
            net.handles.lock().await.insert(id, raft.clone());
            let applied = spawn_apply_loop(rx, storage.clone(), kek.clone(), audit.clone());
            nodes.insert(id, Node { raft, storage, kek, audit, applied, _dir: dir });
        }
        nodes
    }

    async fn leader_of(nodes: &HashMap<u64, Node>) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                for (&id, n) in nodes {
                    if n.raft.inspect().await.0 == Role::Leader {
                        return id;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no leader")
    }

    #[tokio::test]
    async fn a_committed_write_reaches_every_nodes_storage_and_a_seal_seals_every_node() {
        let nodes = three_nodes().await;
        let leader = leader_of(&nodes).await;

        let put = Command::Put { key: "db-password".into(), value: vec![0xAA, 0xBB] };
        let index = nodes[&leader].raft.propose_and_wait(put.encode(), Duration::from_secs(5)).await.unwrap();

        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied index {index}"))
                .unwrap();
            assert_eq!(node.storage.get("secrets/db-password").await.unwrap(), vec![0xAA, 0xBB], "node {id}");
        }

        // A seal proposed on the leader seals the leader AND both followers.
        let seal = Command::Seal { reason: "cluster-wide test".into() };
        let seal_index = nodes[&leader].raft.propose_and_wait(seal.encode(), Duration::from_secs(5)).await.unwrap();
        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= seal_index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied the seal"))
                .unwrap();
            assert!(node.kek.lock().await.is_none(), "node {id} must be sealed");
            assert!(node.audit.lock().await.entries().iter().any(|e| e.event.contains("cluster-wide seal command")), "node {id}");
        }
    }
}