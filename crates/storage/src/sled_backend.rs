use async_trait::async_trait;

use crate::{Storage, StorageError};

/// `sled`-backed implementation of `Storage`. `sled::Db` is internally
/// `Arc`-wrapped and cheap to clone, and its operations are blocking, so
/// every call here runs inside `spawn_blocking` to avoid stalling the
/// Tokio runtime's async worker threads on disk I/O.
#[derive(Clone)]
pub struct SledStorage {
    db: sled::Db,
}

impl SledStorage {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let db = sled::open(path).map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Self { db })
    }
}

#[async_trait]
impl Storage for SledStorage {
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let db = self.db.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            db.get(key.as_bytes())
                .map_err(|e| StorageError::Backend(e.to_string()))?
                .map(|ivec| ivec.to_vec())
                .ok_or(StorageError::NotFound(key))
        })
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        let db = self.db.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            db.insert(key.as_bytes(), value)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            db.flush().map_err(|e| StorageError::Backend(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let db = self.db.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            db.remove(key.as_bytes())
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            db.flush().map_err(|e| StorageError::Backend(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let db = self.db.clone();
        let prefix = prefix.to_owned();
        tokio::task::spawn_blocking(move || {
            db.scan_prefix(prefix.as_bytes())
                .keys()
                .map(|res| {
                    res.map_err(|e| StorageError::Backend(e.to_string())).map(|ivec| {
                        String::from_utf8_lossy(&ivec).into_owned()
                    })
                })
                .collect::<Result<Vec<String>, StorageError>>()
        })
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_storage() -> (SledStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = SledStorage::open(dir.path().to_str().unwrap()).unwrap();
        (storage, dir)
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let (storage, _dir) = temp_storage().await;
        storage.put("secrets/db-password", b"hunter2".to_vec()).await.unwrap();
        let value = storage.get("secrets/db-password").await.unwrap();
        assert_eq!(value, b"hunter2");
    }

    #[tokio::test]
    async fn get_missing_key_returns_not_found() {
        let (storage, _dir) = temp_storage().await;
        let err = storage.get("does/not/exist").await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let (storage, _dir) = temp_storage().await;
        storage.put("k", vec![1, 2, 3]).await.unwrap();
        storage.delete("k").await.unwrap();
        assert!(matches!(storage.get("k").await, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn list_returns_only_matching_prefix() {
        let (storage, _dir) = temp_storage().await;
        storage.put("secrets/a", vec![1]).await.unwrap();
        storage.put("secrets/b", vec![2]).await.unwrap();
        storage.put("audit/c", vec![3]).await.unwrap();

        let mut keys = storage.list("secrets/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["secrets/a".to_string(), "secrets/b".to_string()]);
    }
}