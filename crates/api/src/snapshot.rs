//! Snapshots of the replicated state machine.
//!
//! The Raft log is trimmed once the state machine can stand in for it: after
//! applying entry `N`, the node serializes everything the log has built up
//! into an *image* and tells Raft to forget the entries up to `N`. A node that
//! falls behind the trimmed log is sent the image instead of the entries.
//!
//! # What an image holds
//!
//! * every secret, **still encrypted** (the key-encryption key is never in an
//!   image, and an image can be served by a node that is sealed);
//! * `last_seal_index`: the log index of the last committed cluster-wide
//!   `Seal`. Sealing only changes memory, so without this a node caught up by
//!   an image would skip a seal that replaying the log would have applied, and
//!   stay unsealed while the rest of the cluster is sealed.
//!
//! # What it does not hold
//!
//! The key canary (installed from its file at start-up, not through Raft), the
//! KEK, the sealed state itself and the applied-index checkpoint (set from the
//! snapshot's own index when it is installed).

use std::collections::HashSet;

use bincode::Options;
use sentinel_consensus::{InstallSnapshotRequest, MAX_SNAPSHOT_BYTES, RaftHandle};
use sentinel_storage::{Storage, StorageError};
use serde::{Deserialize, Serialize};

use crate::statemachine::SECRETS_PREFIX;

/// Storage key holding the log index of the last `Seal` this node applied.
pub const LAST_SEAL_KEY: &str = "sys/last-seal-index";

const IMAGE_VERSION: u8 = 1;
/// Room above the size cap for the encoding's own length prefixes.
const DECODE_SLACK: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    /// Log index of the last committed `Seal` applied (0: none ever).
    pub last_seal_index: u64,
    /// `(storage key, encrypted value)` for every secret.
    pub secrets: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("the state is larger than a snapshot may be ({size} bytes against a limit of {max})")]
    TooLarge { size: usize, max: usize },
    #[error("{0}")]
    Storage(#[from] StorageError),
    #[error("malformed snapshot: {0}")]
    Malformed(String),
}

fn codec(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(limit)
}

/// The HTTP body of an `InstallSnapshot`: bincode, not JSON, because JSON
/// would spell every byte of the image as a decimal number (about four times
/// the size, for something that may be tens of megabytes).
pub fn encode_request(req: &InstallSnapshotRequest) -> Result<Vec<u8>, ImageError> {
    codec(MAX_SNAPSHOT_BYTES as u64 + DECODE_SLACK)
        .serialize(req)
        .map_err(|e| ImageError::Malformed(e.to_string()))
}

pub fn decode_request(bytes: &[u8]) -> Result<InstallSnapshotRequest, ImageError> {
    codec(MAX_SNAPSHOT_BYTES as u64 + DECODE_SLACK)
        .deserialize(bytes)
        .map_err(|e| ImageError::Malformed(e.to_string()))
}

/// The most a request body for the snapshot route may be.
pub const MAX_REQUEST_BODY: usize = MAX_SNAPSHOT_BYTES + DECODE_SLACK as usize;

/// Reads a big-endian `u64` stored under `key` (0 if the key does not exist).
pub async fn load_u64(storage: &dyn Storage, key: &str) -> Result<u64, StorageError> {
    match storage.get(key).await {
        Ok(bytes) => {
            let arr: [u8; 8] = bytes
                .try_into()
                .map_err(|_| StorageError::Backend(format!("{key} is not 8 bytes")))?;
            Ok(u64::from_be_bytes(arr))
        }
        Err(StorageError::NotFound(_)) => Ok(0),
        Err(e) => Err(e),
    }
}

/// Serializes the current secrets into an image no larger than `max_bytes`.
///
/// Must be called from the apply loop (the only writer), so what it reads is
/// the state after exactly the entry just applied.
pub async fn build_image(storage: &dyn Storage, max_bytes: usize) -> Result<Vec<u8>, ImageError> {
    let keys = storage.list(SECRETS_PREFIX).await?;
    let mut secrets = Vec::with_capacity(keys.len());
    let mut total = 0usize;
    for key in keys {
        let value = match storage.get(&key).await {
            Ok(v) => v,
            Err(StorageError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        total += key.len() + value.len() + 16;
        if total > max_bytes {
            return Err(ImageError::TooLarge {
                size: total,
                max: max_bytes,
            });
        }
        secrets.push((key, value));
    }
    let image = Image {
        last_seal_index: load_u64(storage, LAST_SEAL_KEY).await?,
        secrets,
    };
    encode_image(&image, max_bytes)
}

/// The bytes of an image: a version byte, then bincode.
pub fn encode_image(image: &Image, max_bytes: usize) -> Result<Vec<u8>, ImageError> {
    let mut out = vec![IMAGE_VERSION];
    out.extend(
        codec(max_bytes as u64 + DECODE_SLACK)
            .serialize(image)
            .map_err(|e| ImageError::Malformed(e.to_string()))?,
    );
    if out.len() > max_bytes {
        return Err(ImageError::TooLarge {
            size: out.len(),
            max: max_bytes,
        });
    }
    Ok(out)
}

/// Parses an image received from a leader. Nothing in it can name a key
/// outside `secrets/`: an image may replace the secrets, never the
/// checkpoint, the canary or any other system key.
pub fn decode_image(bytes: &[u8]) -> Result<Image, ImageError> {
    let (version, rest) = bytes
        .split_first()
        .ok_or_else(|| ImageError::Malformed("empty".into()))?;
    if *version != IMAGE_VERSION {
        return Err(ImageError::Malformed(format!(
            "unsupported version {version}"
        )));
    }
    let image: Image = codec(MAX_SNAPSHOT_BYTES as u64 + DECODE_SLACK)
        .deserialize(rest)
        .map_err(|e| ImageError::Malformed(e.to_string()))?;
    if let Some((key, _)) = image
        .secrets
        .iter()
        .find(|(k, _)| !k.starts_with(SECRETS_PREFIX))
    {
        return Err(ImageError::Malformed(format!(
            "it names a key outside {SECRETS_PREFIX}: {key:?}"
        )));
    }
    Ok(image)
}

/// Makes the secrets in storage exactly those of `image`: keys not in it are
/// deleted, the rest are written, and the seal marker is replaced.
///
/// Not atomic, and it does not have to be: the caller records the applied
/// index only afterwards, so a crash in the middle leaves the old checkpoint,
/// Raft hands the same snapshot over again after the restart, and this runs
/// again from the start. (Until it finishes, a read on this node can see a
/// mixture of old and new secrets.)
pub async fn restore_image(storage: &dyn Storage, image: &Image) -> Result<(), StorageError> {
    let keep: HashSet<&str> = image.secrets.iter().map(|(k, _)| k.as_str()).collect();
    for key in storage.list(SECRETS_PREFIX).await? {
        if !keep.contains(key.as_str()) {
            match storage.delete(&key).await {
                Ok(()) | Err(StorageError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    for (key, value) in &image.secrets {
        storage.put(key, value.clone()).await?;
    }
    storage
        .put(LAST_SEAL_KEY, image.last_seal_index.to_be_bytes().to_vec())
        .await
}

/// When the node snapshots itself.
#[derive(Clone)]
pub struct SnapshotPolicy {
    pub raft: RaftHandle,
    /// Take an image once this many entries have been applied since the last
    /// snapshot.
    pub threshold: u64,
    /// Keep this many entries beyond the image, so a follower that is only a
    /// little behind is served entries and not a whole snapshot.
    pub tail: u64,
    pub max_image_bytes: usize,
}

impl SnapshotPolicy {
    pub fn new(raft: RaftHandle, threshold: u64) -> Self {
        Self {
            raft,
            threshold,
            tail: (threshold / 10).min(100),
            max_image_bytes: MAX_SNAPSHOT_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_storage::SledStorage;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn open() -> (Arc<dyn Storage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        (storage, dir)
    }

    async fn secrets_of(storage: &dyn Storage) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for key in storage.list(SECRETS_PREFIX).await.unwrap() {
            out.push((key.clone(), storage.get(&key).await.unwrap()));
        }
        out.sort();
        out
    }

    async fn filled() -> (Arc<dyn Storage>, tempfile::TempDir) {
        let (s, dir) = open();
        s.put("secrets/a", vec![1, 1]).await.unwrap();
        s.put("secrets/b", vec![2]).await.unwrap();
        s.put("secrets/deep/c", vec![3, 3, 3]).await.unwrap();
        s.put(LAST_SEAL_KEY, 7u64.to_be_bytes().to_vec())
            .await
            .unwrap();
        s.put("sys/kek-canary", vec![0xCA]).await.unwrap();
        (s, dir)
    }

    #[tokio::test]
    async fn restoring_an_image_makes_the_secrets_match_exactly_and_touches_nothing_else() {
        let (source, _d1) = filled().await;
        let image =
            decode_image(&build_image(&*source, MAX_SNAPSHOT_BYTES).await.unwrap()).unwrap();
        assert_eq!(image.last_seal_index, 7);
        assert_eq!(image.secrets.len(), 3);

        let (target, _d2) = open();
        target.put("secrets/b", vec![99]).await.unwrap(); // stale value
        target.put("secrets/extra", vec![5]).await.unwrap(); // not in the image
        target.put("sys/kek-canary", vec![0xBE]).await.unwrap();
        target
            .put("sys/applied-index", 4u64.to_be_bytes().to_vec())
            .await
            .unwrap();

        restore_image(&*target, &image).await.unwrap();

        assert_eq!(secrets_of(&*target).await, secrets_of(&*source).await);
        assert_eq!(load_u64(&*target, LAST_SEAL_KEY).await.unwrap(), 7);
        // The canary and the checkpoint are not the image's to change.
        assert_eq!(target.get("sys/kek-canary").await.unwrap(), vec![0xBE]);
        assert_eq!(load_u64(&*target, "sys/applied-index").await.unwrap(), 4);
    }

    #[tokio::test]
    async fn an_image_of_an_empty_vault_empties_the_target() {
        let (source, _d1) = open();
        let image =
            decode_image(&build_image(&*source, MAX_SNAPSHOT_BYTES).await.unwrap()).unwrap();
        let (target, _d2) = filled().await;
        restore_image(&*target, &image).await.unwrap();
        assert!(secrets_of(&*target).await.is_empty());
        assert_eq!(load_u64(&*target, LAST_SEAL_KEY).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_size_limit_is_exact() {
        let (s, _d) = filled().await;
        let len = build_image(&*s, MAX_SNAPSHOT_BYTES).await.unwrap().len();
        assert!(build_image(&*s, len).await.is_ok());
        assert!(matches!(
            build_image(&*s, len - 1).await,
            Err(ImageError::TooLarge { .. })
        ));
        assert!(matches!(
            build_image(&*s, 10).await,
            Err(ImageError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn a_hostile_or_damaged_image_is_refused() {
        let (s, _d) = filled().await;
        let good = build_image(&*s, MAX_SNAPSHOT_BYTES).await.unwrap();
        assert!(decode_image(&good).is_ok());

        let refused = |bytes: &[u8]| matches!(decode_image(bytes), Err(ImageError::Malformed(_)));
        assert!(refused(&[]), "empty");
        let mut other_version = good.clone();
        other_version[0] = 9;
        assert!(refused(&other_version), "unknown version");
        assert!(refused(&good[..good.len() - 3]), "truncated");
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(refused(&trailing), "trailing bytes");

        // A hostile length prefix must not allocate what it claims.
        let mut hostile = vec![IMAGE_VERSION];
        hostile.extend(0u64.to_le_bytes());
        hostile.extend(u64::MAX.to_le_bytes());
        assert!(refused(&hostile), "absurd entry count");

        // An image may only name secrets: never the checkpoint or the canary.
        for key in ["sys/applied-index", "sys/kek-canary", "secrets", "other"] {
            let evil = Image {
                last_seal_index: 0,
                secrets: vec![(key.to_string(), vec![1])],
            };
            let bytes = encode_image(&evil, MAX_SNAPSHOT_BYTES).unwrap();
            assert!(refused(&bytes), "{key}");
        }
    }

    /// Fails every write after `writes_left` have gone through.
    struct FailAfter {
        inner: Arc<dyn Storage>,
        writes_left: AtomicUsize,
    }

    impl FailAfter {
        fn spend(&self) -> Result<(), StorageError> {
            // One task uses this at a time, so load-then-store is enough.
            let left = self.writes_left.load(Ordering::SeqCst);
            if left == 0 {
                return Err(StorageError::Backend("injected failure".into()));
            }
            self.writes_left.store(left - 1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl Storage for FailAfter {
        async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
            self.spend()?;
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.spend()?;
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
            self.inner.list(prefix).await
        }
    }

    #[tokio::test]
    async fn a_restore_interrupted_at_any_write_is_finished_by_doing_it_again() {
        let (source, _d1) = filled().await;
        let image =
            decode_image(&build_image(&*source, MAX_SNAPSHOT_BYTES).await.unwrap()).unwrap();
        // Stale target: one key to update, one to delete, others missing.
        // This restore makes 5 writes: one delete, three puts, the seal marker.
        for writes_allowed in 0..5 {
            let (target, _d2) = open();
            target.put("secrets/b", vec![99]).await.unwrap();
            target.put("secrets/extra", vec![5]).await.unwrap();
            let flaky = FailAfter {
                inner: target.clone(),
                writes_left: AtomicUsize::new(writes_allowed),
            };
            let outcome = restore_image(&flaky, &image).await;
            assert!(
                outcome.is_err(),
                "allowing {writes_allowed} writes should not be enough"
            );
            // The node restarts; Raft hands the same snapshot over again.
            restore_image(&*target, &image).await.unwrap();
            assert_eq!(
                secrets_of(&*target).await,
                secrets_of(&*source).await,
                "after an interruption at write {writes_allowed}"
            );
            assert_eq!(load_u64(&*target, LAST_SEAL_KEY).await.unwrap(), 7);
        }
        // And with exactly enough writes it simply works.
        let (target, _d3) = open();
        target.put("secrets/extra", vec![5]).await.unwrap();
        let enough = FailAfter {
            inner: target.clone(),
            writes_left: AtomicUsize::new(5),
        };
        restore_image(&enough, &image).await.unwrap();
        assert_eq!(secrets_of(&*target).await, secrets_of(&*source).await);
    }

    #[test]
    fn the_http_body_is_far_smaller_than_json_would_be_and_round_trips() {
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8 + 4).collect();
        let req = InstallSnapshotRequest {
            term: 3,
            leader_id: 2,
            last_included_index: 99,
            last_included_term: 2,
            data: data.clone(),
        };
        let body = encode_request(&req).unwrap();
        assert!(body.len() < data.len() + 64, "{} bytes", body.len());
        assert!(serde_json::to_vec(&req).unwrap().len() > 2 * data.len());
        let back = decode_request(&body).unwrap();
        assert_eq!(
            (
                back.term,
                back.leader_id,
                back.last_included_index,
                back.last_included_term
            ),
            (3, 2, 99, 2)
        );
        assert_eq!(back.data, data);
        assert!(decode_request(&body[..body.len() / 2]).is_err());
        assert!(decode_request(b"{}").is_err());
    }
}
