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
//! The log is trimmed by snapshots (see [`crate::snapshot`]): after applying
//! enough entries the loop serializes the secrets and asks Raft to forget the
//! entries they replace, and a node that fell behind the trimmed log receives
//! the image in place of the entries.
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
use sentinel_consensus::{ApplyItem, LogEntry};
use sentinel_crypto::SecretBytes;
use sentinel_storage::{Storage, StorageError};

use crate::snapshot::{LAST_SEAL_KEY, SnapshotPolicy, build_image, decode_image, restore_image};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, watch};

/// Where the applied-log-index checkpoint lives. Outside `secrets/`, so it is
/// never listed as a secret.
pub const APPLIED_INDEX_KEY: &str = "sys/applied-index";

const WIRE_VERSION: u8 = 1;
const MAX_COMMAND_BYTES: u64 = 8 * 1024 * 1024;

/// Every secret lives under this prefix; a snapshot covers exactly these keys.
pub const SECRETS_PREFIX: &str = "secrets/";

/// Storage key for a secret named `key`.
pub fn storage_key(key: &str) -> String {
    format!("{SECRETS_PREFIX}{key}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// `value` is a bincode-encoded `EnvelopeCiphertext`, never plaintext.
    Put {
        key: String,
        value: Vec<u8>,
    },
    Delete {
        key: String,
    },
    /// Seal every node. `reason` is free text for the audit log.
    Seal {
        reason: String,
    },
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_COMMAND_BYTES)
}

impl Command {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        out.extend(
            codec()
                .serialize(self)
                .expect("a Command always serializes"),
        );
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
///
/// The same loop without snapshotting; the node itself starts
/// [`spawn_apply_loop_with_snapshots`], so this is for tests.
#[cfg(test)]
pub fn spawn_apply_loop(
    committed: mpsc::UnboundedReceiver<ApplyItem>,
    storage: Arc<dyn Storage>,
    kek: Arc<Mutex<Option<SecretBytes>>>,
    audit: Arc<Mutex<AuditChain>>,
) -> watch::Receiver<u64> {
    spawn_apply_loop_with_snapshots(committed, storage, kek, audit, None)
}

/// [`spawn_apply_loop`] that also snapshots the state according to `policy`
/// (and installs snapshots a leader sends; that part is always on).
pub fn spawn_apply_loop_with_snapshots(
    mut committed: mpsc::UnboundedReceiver<ApplyItem>,
    storage: Arc<dyn Storage>,
    kek: Arc<Mutex<Option<SecretBytes>>>,
    audit: Arc<Mutex<AuditChain>>,
    policy: Option<SnapshotPolicy>,
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

        // Where the last snapshot is, and an image taken but not yet used to
        // compact (it waits for `tail` more entries to be applied).
        let mut last_snapshot = match &policy {
            Some(p) => p
                .raft
                .snapshot_status()
                .await
                .map_or(0, |s| s.snapshot_index),
            None => 0,
        };
        let mut pending: Option<(u64, Vec<u8>)> = None;

        while let Some(item) = committed.recv().await {
            let entry = match item {
                ApplyItem::Entry(entry) => entry,
                ApplyItem::Snapshot { index, .. } if index <= applied => {
                    // Already reflected in storage (replayed after a restart).
                    advance(&applied_tx, index);
                    continue;
                }
                ApplyItem::Snapshot { index, data, .. } => {
                    match restore_from_snapshot(&*storage, &kek, &audit, applied, index, &data)
                        .await
                    {
                        Ok(()) => {
                            applied = index;
                            last_snapshot = index;
                            pending = None;
                            advance(&applied_tx, applied);
                            continue;
                        }
                        Err(e) => {
                            // Raft already treats everything up to `index` as
                            // applied, so skipping it would diverge silently.
                            tracing::error!(index, applied, error = %e, "cannot install a snapshot; stopping the state machine");
                            break;
                        }
                    }
                }
            };
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
            if let Err(e) = storage
                .put(APPLIED_INDEX_KEY, applied.to_be_bytes().to_vec())
                .await
            {
                tracing::error!(error = %e, "failed to record the applied index; stopping the state machine");
                break;
            }
            advance(&applied_tx, applied);
            if let Some(policy) = &policy {
                maybe_snapshot(policy, &*storage, applied, &mut last_snapshot, &mut pending).await;
            }
        }
    });

    applied_rx
}

/// Takes an image when enough entries have been applied since the last
/// snapshot, and compacts the log to it once `tail` more have followed.
async fn maybe_snapshot(
    policy: &SnapshotPolicy,
    storage: &dyn Storage,
    applied: u64,
    last_snapshot: &mut u64,
    pending: &mut Option<(u64, Vec<u8>)>,
) {
    if pending.is_none() && policy.threshold > 0 && applied >= *last_snapshot + policy.threshold {
        match build_image(storage, policy.max_image_bytes).await {
            Ok(image) => *pending = Some((applied, image)),
            Err(e) => {
                // Not fatal: the log just keeps growing. Try again a whole
                // threshold from now rather than on every entry.
                tracing::error!(error = %e, applied, "cannot take a snapshot; the Raft log will keep growing");
                *last_snapshot = applied;
            }
        }
    }
    if let Some((index, _)) = pending
        && applied >= *index + policy.tail
    {
        let (index, image) = pending.take().expect("checked just above");
        match policy.raft.compact(index, image).await {
            Ok(()) => *last_snapshot = index,
            Err(e) => {
                tracing::error!(error = %e, index, "Raft refused the snapshot; the log will keep growing");
                *last_snapshot = applied;
            }
        }
    }
}

/// Replaces this node's secrets with those of a snapshot sent by a leader.
/// The applied-index checkpoint is written last, so an interrupted restore is
/// simply done again after a restart.
async fn restore_from_snapshot(
    storage: &dyn Storage,
    kek: &Mutex<Option<SecretBytes>>,
    audit: &Mutex<AuditChain>,
    applied_before: u64,
    index: u64,
    data: &[u8],
) -> Result<(), String> {
    let image = decode_image(data).map_err(|e| e.to_string())?;
    restore_image(storage, &image)
        .await
        .map_err(|e| e.to_string())?;
    if image.last_seal_index > applied_before {
        // A cluster-wide seal happened in the part of the log this node is
        // skipping. Replaying that log would have sealed it, so do the same.
        *kek.lock().await = None;
        audit.lock().await.append(format!(
            "vault SEALED: the snapshot installed here covers a cluster-wide seal (log index {}) that this node had not applied",
            image.last_seal_index
        ));
    }
    audit.lock().await.append(format!(
        "state restored from a snapshot at log index {index} (this node had applied up to {applied_before})"
    ));
    storage
        .put(APPLIED_INDEX_KEY, index.to_be_bytes().to_vec())
        .await
        .map_err(|e| e.to_string())
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
            let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                StorageError::Backend("applied-index checkpoint is not 8 bytes".into())
            })?;
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
            audit.lock().await.append(format!(
                "ignored an undecodable committed command at log index {}",
                entry.index
            ));
        }
        Some(Command::Put { key, value }) => storage.put(&storage_key(&key), value).await?,
        Some(Command::Delete { key }) => match storage.delete(&storage_key(&key)).await {
            Ok(()) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        },
        Some(Command::Seal { reason }) => {
            *kek.lock().await = None;
            audit.lock().await.append(format!(
                "vault SEALED by a committed cluster-wide seal command (log index {}): {reason}",
                entry.index
            ));
            // Remembered so that a snapshot taken later carries it (sealing
            // itself only changes memory).
            storage
                .put(LAST_SEAL_KEY, entry.index.to_be_bytes().to_vec())
                .await?;
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
            Command::Put {
                key: "db".into(),
                value: vec![1, 2, 3],
            },
            Command::Delete { key: "db".into() },
            Command::Seal {
                reason: "anomaly".into(),
            },
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
        assert_eq!(
            Command::decode(&trailing),
            None,
            "trailing bytes are rejected"
        );

        // A hostile length prefix must not allocate gigabytes.
        let hostile = [
            1u8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        assert_eq!(Command::decode(&hostile), None);
    }

    struct Harness {
        tx: mpsc::UnboundedSender<ApplyItem>,
        storage: Arc<dyn Storage>,
        kek: Arc<Mutex<Option<SecretBytes>>>,
        audit: Arc<Mutex<AuditChain>>,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn harness_with_applied(applied_index: Option<u64>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        if let Some(i) = applied_index {
            storage
                .put(APPLIED_INDEX_KEY, i.to_be_bytes().to_vec())
                .await
                .unwrap();
        }
        let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
        let audit = Arc::new(Mutex::new(AuditChain::new()));
        let (tx, rx) = mpsc::unbounded_channel();
        let applied = spawn_apply_loop(rx, storage.clone(), kek.clone(), audit.clone());
        Harness {
            tx,
            storage,
            kek,
            audit,
            applied,
            _dir: dir,
        }
    }

    fn entry(index: u64, cmd: &Command) -> ApplyItem {
        ApplyItem::Entry(LogEntry {
            term: 1,
            index,
            command: cmd.encode(),
        })
    }

    async fn wait_applied(h: &Harness, index: u64) {
        let mut rx = h.applied.clone();
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index))
            .await
            .expect("timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn committed_puts_and_deletes_change_storage_and_report_progress() {
        let h = harness_with_applied(None).await;
        h.tx.send(entry(
            1,
            &Command::Put {
                key: "a".into(),
                value: vec![9, 9],
            },
        ))
        .unwrap();
        wait_applied(&h, 1).await;
        assert_eq!(h.storage.get("secrets/a").await.unwrap(), vec![9, 9]);

        h.tx.send(entry(2, &Command::Delete { key: "a".into() }))
            .unwrap();
        h.tx.send(entry(
            3,
            &Command::Delete {
                key: "never-existed".into(),
            },
        ))
        .unwrap();
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
        h.tx.send(entry(
            1,
            &Command::Seal {
                reason: "test anomaly".into(),
            },
        ))
        .unwrap();
        wait_applied(&h, 1).await;

        assert!(h.kek.lock().await.is_none());
        let chain = h.audit.lock().await;
        assert!(chain.verify().is_ok());
        assert!(
            chain
                .entries()
                .iter()
                .any(|e| e.event.contains("committed cluster-wide seal command")
                    && e.event.contains("test anomaly"))
        );
    }

    #[tokio::test]
    async fn entries_at_or_below_the_checkpoint_are_skipped_on_replay() {
        // The node already applied up to index 5 before it restarted.
        let h = harness_with_applied(Some(5)).await;
        wait_applied(&h, 5).await;

        // Replay delivers old entries again, including an old Seal. It must NOT
        // re-seal a node that was unsealed since, nor redo the old write.
        h.tx.send(entry(
            3,
            &Command::Seal {
                reason: "ancient".into(),
            },
        ))
        .unwrap();
        h.tx.send(entry(
            4,
            &Command::Put {
                key: "stale".into(),
                value: vec![1],
            },
        ))
        .unwrap();
        h.tx.send(entry(
            6,
            &Command::Put {
                key: "fresh".into(),
                value: vec![2],
            },
        ))
        .unwrap();
        wait_applied(&h, 6).await;

        assert!(
            h.kek.lock().await.is_some(),
            "an old seal must not be replayed"
        );
        assert!(h.storage.get("secrets/stale").await.is_err());
        assert_eq!(h.storage.get("secrets/fresh").await.unwrap(), vec![2]);
    }

    #[tokio::test]
    async fn an_undecodable_committed_entry_is_skipped_visibly_without_stalling() {
        let h = harness_with_applied(None).await;
        h.tx.send(ApplyItem::Entry(LogEntry {
            term: 1,
            index: 1,
            command: b"not a command".to_vec(),
        }))
        .unwrap();
        h.tx.send(entry(
            2,
            &Command::Put {
                key: "after".into(),
                value: vec![5],
            },
        ))
        .unwrap();
        wait_applied(&h, 2).await;

        assert_eq!(h.storage.get("secrets/after").await.unwrap(), vec![5]);
        assert!(h.audit.lock().await.entries().iter().any(|e| {
            e.event
                .contains("undecodable committed command at log index 1")
        }));
    }

    // ---- three real nodes ----

    use crate::snapshot::{Image, SnapshotPolicy, encode_image, load_u64};
    use sentinel_consensus::{
        AppendEntriesRequest, AppendEntriesResponse, ElectionTimeoutRange, InstallSnapshotRequest,
        InstallSnapshotResponse, MAX_SNAPSHOT_BYTES, MemoryStore, RaftHandle, RequestVoteRequest,
        RequestVoteResponse, Role, Transport, TransportError, spawn_raft_actor_persistent,
        spawn_raft_actor_with_apply,
    };
    use std::collections::{HashMap, HashSet};

    struct Loopback {
        handles: Mutex<HashMap<u64, RaftHandle>>,
        /// Nodes cut off from everyone (in both directions).
        blocked: std::sync::Mutex<HashSet<u64>>,
    }
    /// A transport for the node with the given id.
    struct LoopTransport(Arc<Loopback>, u64);

    impl LoopTransport {
        async fn peer(&self, id: u64) -> Result<RaftHandle, TransportError> {
            {
                let blocked = self.0.blocked.lock().unwrap();
                if blocked.contains(&id) || blocked.contains(&self.1) {
                    return Err(TransportError::Unreachable(id));
                }
            }
            self.0
                .handles
                .lock()
                .await
                .get(&id)
                .cloned()
                .ok_or(TransportError::Unreachable(id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for LoopTransport {
        async fn send_request_vote(
            &self,
            p: u64,
            req: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.peer(p).await?.request_vote(req).await)
        }
        async fn send_append_entries(
            &self,
            p: u64,
            req: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.peer(p).await?.append_entries(req).await)
        }
        async fn send_install_snapshot(
            &self,
            p: u64,
            req: InstallSnapshotRequest,
        ) -> Result<InstallSnapshotResponse, TransportError> {
            Ok(self.peer(p).await?.install_snapshot(req).await)
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
        build_three(None).await.0
    }

    /// Three nodes; with `Some(threshold)` each also snapshots its state
    /// every `threshold` applied entries (and trims its log at once).
    async fn build_three(threshold: Option<u64>) -> (HashMap<u64, Node>, Arc<Loopback>) {
        let ids = [1u64, 2, 3];
        let net = Arc::new(Loopback {
            handles: Mutex::new(HashMap::new()),
            blocked: Default::default(),
        });
        let mut nodes = HashMap::new();
        for &id in &ids {
            let dir = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> =
                Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
            let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
            let audit = Arc::new(Mutex::new(AuditChain::new()));
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let (raft, rx) = spawn_raft_actor_with_apply(
                id,
                peers,
                Arc::new(LoopTransport(net.clone(), id)),
                Duration::from_millis(20),
                ElectionTimeoutRange {
                    min_ms: 80,
                    max_ms: 150,
                },
            );
            net.handles.lock().await.insert(id, raft.clone());
            let policy = threshold.map(|t| SnapshotPolicy {
                raft: raft.clone(),
                threshold: t,
                tail: 0,
                max_image_bytes: MAX_SNAPSHOT_BYTES,
            });
            let applied = spawn_apply_loop_with_snapshots(
                rx,
                storage.clone(),
                kek.clone(),
                audit.clone(),
                policy,
            );
            nodes.insert(
                id,
                Node {
                    raft,
                    storage,
                    kek,
                    audit,
                    applied,
                    _dir: dir,
                },
            );
        }
        (nodes, net)
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

    /// Proposes `command` through whichever node is leader *right now* and
    /// waits for the commit, retrying across leadership changes. A single
    /// "find the leader, then propose" snapshot is not enough on a loaded
    /// machine: leadership can move in between and the proposal comes back
    /// `NotLeader`. A retry after an error can in principle commit the
    /// command twice (a timed-out proposal may still commit later), which is
    /// harmless for the idempotent commands these tests use.
    async fn commit_via_any_leader(nodes: &HashMap<u64, Node>, command: &Command) -> u64 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut last_error = String::from("no leader found");
        while tokio::time::Instant::now() < deadline {
            for n in nodes.values() {
                if n.raft.inspect().await.0 == Role::Leader {
                    match n
                        .raft
                        .propose_and_wait(command.encode(), Duration::from_secs(2))
                        .await
                    {
                        Ok(index) => return index,
                        Err(e) => last_error = e.to_string(),
                    }
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("could not commit through any leader within 30 s (last error: {last_error})");
    }

    #[tokio::test]
    async fn a_committed_write_reaches_every_nodes_storage_and_a_seal_seals_every_node() {
        let nodes = three_nodes().await;
        leader_of(&nodes).await;

        let put = Command::Put {
            key: "db-password".into(),
            value: vec![0xAA, 0xBB],
        };
        let index = commit_via_any_leader(&nodes, &put).await;

        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied index {index}"))
                .unwrap();
            assert_eq!(
                node.storage.get("secrets/db-password").await.unwrap(),
                vec![0xAA, 0xBB],
                "node {id}"
            );
        }

        // A seal proposed on the leader seals the leader AND both followers.
        let seal = Command::Seal {
            reason: "cluster-wide test".into(),
        };
        let seal_index = commit_via_any_leader(&nodes, &seal).await;
        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= seal_index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied the seal"))
                .unwrap();
            assert!(node.kek.lock().await.is_none(), "node {id} must be sealed");
            assert!(
                node.audit
                    .lock()
                    .await
                    .entries()
                    .iter()
                    .any(|e| e.event.contains("cluster-wide seal command")),
                "node {id}"
            );
        }
    }

    #[tokio::test]
    async fn a_snapshot_already_covered_is_skipped_and_an_undecodable_one_stops_the_loop_loudly() {
        let h = harness_with_applied(Some(5)).await;
        let snap = |index| ApplyItem::Snapshot {
            index,
            term: 1,
            data: vec![1, 2, 3],
        };
        // At or below the checkpoint: nothing to do, and the loop carries on.
        h.tx.send(snap(3)).unwrap();
        h.tx.send(snap(5)).unwrap();
        h.tx.send(entry(
            6,
            &Command::Put {
                key: "k".into(),
                value: vec![1],
            },
        ))
        .unwrap();
        wait_applied(&h, 6).await;

        // Ahead of it but not an image at all: Raft already counts everything
        // up to there as applied, so skipping it would diverge. It must stop.
        h.tx.send(snap(9)).unwrap();
        h.tx.send(entry(
            10,
            &Command::Put {
                key: "never".into(),
                value: vec![2],
            },
        ))
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(*h.applied.borrow(), 6);
        assert!(h.storage.get("secrets/never").await.is_err());
    }

    // ---- snapshots ----

    fn image(last_seal_index: u64, secrets: &[(&str, &[u8])]) -> Vec<u8> {
        encode_image(
            &Image {
                last_seal_index,
                secrets: secrets
                    .iter()
                    .map(|(k, v)| (storage_key(k), v.to_vec()))
                    .collect(),
            },
            MAX_SNAPSHOT_BYTES,
        )
        .unwrap()
    }

    fn snap(index: u64, data: Vec<u8>) -> ApplyItem {
        ApplyItem::Snapshot {
            index,
            term: 1,
            data,
        }
    }

    fn put_cmd(key: &str, value: u8) -> Command {
        Command::Put {
            key: key.into(),
            value: vec![value],
        }
    }

    #[tokio::test]
    async fn a_seal_remembers_the_log_index_it_was_applied_at() {
        let h = harness_with_applied(None).await;
        h.tx.send(entry(4, &Command::Seal { reason: "x".into() }))
            .unwrap();
        wait_applied(&h, 4).await;
        assert_eq!(load_u64(&*h.storage, LAST_SEAL_KEY).await.unwrap(), 4);
    }

    #[tokio::test]
    async fn a_snapshot_ahead_of_the_checkpoint_replaces_the_secrets_and_moves_the_checkpoint() {
        let h = harness_with_applied(Some(5)).await;
        h.storage.put("secrets/old", vec![1]).await.unwrap();
        h.storage.put("secrets/keep", vec![1]).await.unwrap();
        h.storage.put("sys/kek-canary", vec![0xCA]).await.unwrap();

        h.tx.send(snap(9, image(0, &[("keep", &[2]), ("new", &[3])])))
            .unwrap();
        h.tx.send(entry(10, &put_cmd("after", 4))).unwrap();
        wait_applied(&h, 10).await;

        assert!(
            h.storage.get("secrets/old").await.is_err(),
            "not in the snapshot"
        );
        assert_eq!(h.storage.get("secrets/keep").await.unwrap(), vec![2]);
        assert_eq!(h.storage.get("secrets/new").await.unwrap(), vec![3]);
        assert_eq!(h.storage.get("secrets/after").await.unwrap(), vec![4]);
        assert_eq!(
            h.storage.get("sys/kek-canary").await.unwrap(),
            vec![0xCA],
            "the canary is not part of a snapshot"
        );
        assert_eq!(load_u64(&*h.storage, APPLIED_INDEX_KEY).await.unwrap(), 10);
        assert!(h.audit.lock().await.entries().iter().any(|e| {
            e.event
                .contains("state restored from a snapshot at log index 9")
        }));
        assert!(h.kek.lock().await.is_some(), "no seal was in the snapshot");
    }

    #[tokio::test]
    async fn a_snapshot_at_or_below_the_checkpoint_changes_nothing() {
        let h = harness_with_applied(Some(5)).await;
        h.storage.put("secrets/mine", vec![1]).await.unwrap();
        h.tx.send(snap(3, image(0, &[("other", &[9])]))).unwrap();
        h.tx.send(snap(5, image(0, &[("other", &[9])]))).unwrap();
        h.tx.send(entry(6, &put_cmd("next", 2))).unwrap();
        wait_applied(&h, 6).await;
        assert_eq!(h.storage.get("secrets/mine").await.unwrap(), vec![1]);
        assert!(h.storage.get("secrets/other").await.is_err());
    }

    #[tokio::test]
    async fn a_snapshot_that_covers_a_seal_this_node_missed_seals_it_and_one_it_already_applied_does_not()
     {
        // Applied up to 5, the seal was at 7, the snapshot is at 12: missed.
        let h = harness_with_applied(Some(5)).await;
        h.tx.send(snap(12, image(7, &[("k", &[1])]))).unwrap();
        wait_applied(&h, 12).await;
        assert!(h.kek.lock().await.is_none(), "must be sealed");
        assert!(
            h.audit
                .lock()
                .await
                .entries()
                .iter()
                .any(|e| e.event.contains("covers a cluster-wide seal (log index 7)"))
        );
        assert_eq!(h.storage.get("secrets/k").await.unwrap(), vec![1]);

        // Applied up to 9, so the seal at 7 is already behind it; and applied
        // up to exactly 7 means the seal at 7 *was* applied.
        for applied in [9, 7] {
            let h = harness_with_applied(Some(applied)).await;
            h.tx.send(snap(12, image(7, &[("k", &[1])]))).unwrap();
            wait_applied(&h, 12).await;
            assert!(
                h.kek.lock().await.is_some(),
                "applied {applied}: must stay unsealed"
            );
        }
    }

    #[tokio::test]
    async fn an_image_that_names_a_key_outside_the_secrets_is_refused_and_stops_the_loop() {
        let h = harness_with_applied(Some(5)).await;
        let evil = encode_image(
            &Image {
                last_seal_index: 0,
                secrets: vec![("sys/applied-index".into(), vec![0; 8])],
            },
            MAX_SNAPSHOT_BYTES,
        )
        .unwrap();
        h.tx.send(snap(9, evil)).unwrap();
        h.tx.send(entry(10, &put_cmd("never", 1))).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(*h.applied.borrow(), 5);
        assert_eq!(load_u64(&*h.storage, APPLIED_INDEX_KEY).await.unwrap(), 5);
    }

    struct NoPeers;

    #[async_trait::async_trait]
    impl Transport for NoPeers {
        async fn send_request_vote(
            &self,
            p: u64,
            _: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
        async fn send_append_entries(
            &self,
            p: u64,
            _: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
    }

    /// A one-node cluster whose state machine snapshots by `policy`.
    struct Solo {
        raft: RaftHandle,
        storage: Arc<dyn Storage>,
        raft_store: MemoryStore,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn solo(threshold: u64, tail: u64, max_image_bytes: usize) -> Solo {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let raft_store = MemoryStore::new();
        let (raft, rx) = spawn_raft_actor_persistent(
            1,
            vec![],
            Arc::new(NoPeers),
            Duration::from_millis(20),
            ElectionTimeoutRange {
                min_ms: 80,
                max_ms: 150,
            },
            Box::new(raft_store.clone()),
        )
        .unwrap();
        let applied = spawn_apply_loop_with_snapshots(
            rx,
            storage.clone(),
            Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32])))),
            Arc::new(Mutex::new(AuditChain::new())),
            Some(SnapshotPolicy {
                raft: raft.clone(),
                threshold,
                tail,
                max_image_bytes,
            }),
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while raft.inspect().await.0 != Role::Leader {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a single node leads");
        Solo {
            raft,
            storage,
            raft_store,
            applied,
            _dir: dir,
        }
    }

    impl Solo {
        /// Commits `n` puts (k0, k1, ...) and waits until they are applied.
        /// Returns the log index of the last.
        async fn put_n(&self, from: u8, n: u8) -> u64 {
            let mut last = 0;
            for i in from..from + n {
                last = self
                    .raft
                    .propose_and_wait(
                        put_cmd(&format!("k{i}"), i).encode(),
                        Duration::from_secs(10),
                    )
                    .await
                    .unwrap();
            }
            let mut rx = self.applied.clone();
            tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|&v| v >= last))
                .await
                .expect("applied in time")
                .unwrap();
            last
        }

        async fn status_where(
            &self,
            what: &str,
            cond: impl Fn(&sentinel_consensus::SnapshotStatus) -> bool,
        ) -> sentinel_consensus::SnapshotStatus {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let s = self.raft.snapshot_status().await.unwrap();
                    if cond(&s) {
                        return s;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        }
    }

    #[tokio::test]
    async fn the_state_machine_snapshots_every_threshold_entries_and_trims_the_log() {
        let node = solo(5, 0, MAX_SNAPSHOT_BYTES).await;
        // The leader's no-op is entry 1, so these puts are entries 2..=13.
        node.put_n(0, 12).await;
        let s = node.status_where("two snapshots", |s| s.taken >= 2).await;
        assert_eq!((s.taken, s.snapshot_index), (2, 10), "at entries 5 and 10");

        let on_disk = node.raft_store.snapshot();
        assert_eq!(on_disk.snapshot_index, 10);
        let image = crate::snapshot::decode_image(&on_disk.snapshot_data).unwrap();
        let keys: Vec<&str> = image.secrets.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys.len(), 9, "k0..k8 are entries 2..=10: {keys:?}");
        assert!(on_disk.entries.iter().all(|e| e.index > 10));
        assert_eq!(on_disk.entries.first().map(|e| e.index), Some(11));
        // Nothing was lost on the way: all twelve are still readable.
        for i in 0..12u8 {
            assert_eq!(
                node.storage.get(&format!("secrets/k{i}")).await.unwrap(),
                vec![i]
            );
        }
    }

    #[tokio::test]
    async fn the_log_is_trimmed_to_the_image_only_after_the_tail_has_gone_by() {
        let node = solo(5, 3, MAX_SNAPSHOT_BYTES).await;
        node.put_n(0, 6).await; // entries 2..=7: the image at 5 is waiting
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(node.raft.snapshot_status().await.unwrap().taken, 0);

        node.put_n(6, 1).await; // entry 8 = 5 + tail
        let s = node.status_where("the compaction", |s| s.taken >= 1).await;
        assert_eq!(
            s.snapshot_index, 5,
            "to the image's index, not to where it was applied"
        );
        let on_disk = node.raft_store.snapshot();
        assert_eq!(
            on_disk.entries.first().map(|e| e.index),
            Some(6),
            "the tail is kept"
        );

        // The next image is due a whole threshold after the *image* (5 + 5),
        // not after the moment the log was trimmed: it is taken at entry 10
        // and trims the log at entry 13.
        node.put_n(7, 6).await; // entries 9..=14
        let s = node
            .status_where("the second compaction", |s| s.taken >= 2)
            .await;
        assert_eq!((s.taken, s.snapshot_index), (2, 10));
    }

    #[tokio::test]
    async fn the_tail_is_a_tenth_of_the_threshold_and_never_more_than_a_hundred() {
        let (raft, _rx) = sentinel_consensus::spawn_raft_actor_with_apply(
            1,
            vec![],
            Arc::new(NoPeers),
            Duration::from_millis(20),
            ElectionTimeoutRange {
                min_ms: 80,
                max_ms: 150,
            },
        );
        for (threshold, tail) in [
            (1, 0),
            (5, 0),
            (10, 1),
            (100, 10),
            (1000, 100),
            (50_000, 100),
        ] {
            let p = SnapshotPolicy::new(raft.clone(), threshold);
            assert_eq!((p.threshold, p.tail), (threshold, tail), "{threshold}");
            assert_eq!(p.max_image_bytes, MAX_SNAPSHOT_BYTES);
        }
    }

    #[tokio::test]
    async fn a_state_too_big_for_a_snapshot_is_not_fatal_the_log_just_keeps_growing() {
        let node = solo(3, 0, 10).await;
        node.put_n(0, 10).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s = node.raft.snapshot_status().await.unwrap();
        assert_eq!((s.taken, s.snapshot_index), (0, 0));
        for i in 0..10u8 {
            assert_eq!(
                node.storage.get(&format!("secrets/k{i}")).await.unwrap(),
                vec![i]
            );
        }
    }

    async fn commit_among(nodes: &HashMap<u64, Node>, ids: &[u64], command: &Command) -> u64 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::time::Instant::now() < deadline {
            for id in ids {
                if nodes[id].raft.inspect().await.0 == Role::Leader {
                    if let Ok(index) = nodes[id]
                        .raft
                        .propose_and_wait(command.encode(), Duration::from_secs(5))
                        .await
                    {
                        return index;
                    }
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("could not commit among {ids:?} within 30 s");
    }

    async fn secrets_on(node: &Node) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for key in node.storage.list(SECRETS_PREFIX).await.unwrap() {
            out.push((key.clone(), node.storage.get(&key).await.unwrap()));
        }
        out.sort();
        out
    }

    async fn applied_at_least(node: &Node, index: u64, what: &str) {
        let mut rx = node.applied.clone();
        tokio::time::timeout(Duration::from_secs(30), rx.wait_for(|&v| v >= index))
            .await
            .unwrap_or_else(|_| panic!("{what}: never applied index {index}"))
            .unwrap();
    }

    #[tokio::test]
    async fn a_node_that_missed_the_trimmed_log_is_caught_up_by_a_snapshot_including_a_seal_it_missed()
     {
        let (nodes, net) = build_three(Some(6)).await;
        let leader = leader_of(&nodes).await;
        let victim = [1u64, 2, 3].into_iter().find(|&i| i != leader).unwrap();
        let others: Vec<u64> = [1u64, 2, 3].into_iter().filter(|&i| i != victim).collect();
        net.blocked.lock().unwrap().insert(victim);

        for i in 0..8u8 {
            commit_among(&nodes, &others, &put_cmd(&format!("k{i}"), i)).await;
        }
        commit_among(&nodes, &others, &Command::Delete { key: "k1".into() }).await;
        let seal = Command::Seal {
            reason: "while the victim was away".into(),
        };
        commit_among(&nodes, &others, &seal).await;
        let mut last = 0;
        for i in 8..16u8 {
            last = commit_among(&nodes, &others, &put_cmd(&format!("k{i}"), i)).await;
        }
        for &id in &others {
            applied_at_least(&nodes[&id], last, "a reachable node").await;
            let s = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let s = nodes[&id].raft.snapshot_status().await.unwrap();
                    if s.taken >= 1 {
                        return s;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the reachable nodes trim their logs");
            assert!(s.snapshot_index > 0);
        }
        // The victim saw none of it, and still holds its key.
        assert!(nodes[&victim].storage.get("secrets/k0").await.is_err());
        assert!(nodes[&victim].kek.lock().await.is_some());

        net.blocked.lock().unwrap().clear();
        applied_at_least(&nodes[&victim], last, "the victim").await;

        assert_eq!(
            secrets_on(&nodes[&victim]).await,
            secrets_on(&nodes[&others[0]]).await,
            "same secrets as the others"
        );
        assert!(
            nodes[&victim].storage.get("secrets/k1").await.is_err(),
            "the delete was in the part the snapshot replaced"
        );
        assert!(
            nodes[&victim].kek.lock().await.is_none(),
            "the seal it missed must reach it through the snapshot"
        );
        assert!(nodes[&victim].audit.lock().await.entries().iter().any(|e| {
            e.event
                .contains("snapshot installed here covers a cluster-wide seal")
        }));
        let s = nodes[&victim].raft.snapshot_status().await.unwrap();
        assert!(s.installed >= 1, "it was caught up by a snapshot: {s:?}");
    }
}
