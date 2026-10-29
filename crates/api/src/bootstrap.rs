//! Startup provisioning helpers.

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use bincode::Options;
use sentinel_crypto::envelope::EnvelopeCiphertext;
use sentinel_storage::{Storage, StorageError};

use crate::handlers::unseal::CANARY_KEY;

#[derive(Debug, PartialEq, Eq)]
pub enum CanaryOutcome {
    /// The storage had no canary; the one from the file is now installed.
    Installed,
    /// The storage already holds exactly this canary.
    AlreadyPresent,
}

/// Installs the `canary.bin` written by `sentinel-cli init` into `storage`.
///
/// This is what removes the trust-on-first-use weakness: the canary is made at
/// provisioning time, from the real key, before any node ever unseals. A node
/// whose storage already holds a *different* canary belongs to a different
/// vault (or the wrong directory) and refuses to start rather than guess.
pub async fn install_canary(storage: &dyn Storage, path: &Path) -> anyhow::Result<CanaryOutcome> {
    let bytes = std::fs::read(path).with_context(|| format!("reading canary file {}", path.display()))?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(1 << 20)
        .deserialize::<EnvelopeCiphertext>(&bytes)
        .map_err(|e| anyhow!("{} is not a valid canary file: {e}", path.display()))?;

    match storage.get(CANARY_KEY).await {
        Ok(existing) if existing == bytes => Ok(CanaryOutcome::AlreadyPresent),
        Ok(_) => bail!(
            "this node's storage already holds a different key canary than {}: it belongs to a different vault. Refusing to start; check storage_path and canary_file",
            path.display()
        ),
        Err(StorageError::NotFound(_)) => {
            storage.put(CANARY_KEY, bytes).await.context("storing the key canary")?;
            Ok(CanaryOutcome::Installed)
        }
        Err(e) => Err(e).context("reading the existing key canary"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_crypto::{canary, SecretBytes};
    use sentinel_storage::SledStorage;

    fn canary_bytes(key_byte: u8) -> Vec<u8> {
        bincode::serialize(&canary::create(&SecretBytes::new(vec![key_byte; 32])).unwrap()).unwrap()
    }

    fn storage() -> (SledStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (SledStorage::open(dir.path().join("db").to_str().unwrap()).unwrap(), dir)
    }

    #[tokio::test]
    async fn installs_into_empty_storage_and_is_idempotent() {
        let (st, dir) = storage();
        let file = dir.path().join("canary.bin");
        std::fs::write(&file, canary_bytes(1)).unwrap();

        assert_eq!(install_canary(&st, &file).await.unwrap(), CanaryOutcome::Installed);
        assert_eq!(st.get(CANARY_KEY).await.unwrap(), std::fs::read(&file).unwrap());
        assert_eq!(install_canary(&st, &file).await.unwrap(), CanaryOutcome::AlreadyPresent);
    }

    #[tokio::test]
    async fn a_different_canary_already_in_storage_is_a_refusal_not_an_overwrite() {
        let (st, dir) = storage();
        let original = canary_bytes(1);
        st.put(CANARY_KEY, original.clone()).await.unwrap();
        let file = dir.path().join("canary.bin");
        std::fs::write(&file, canary_bytes(2)).unwrap();

        let err = install_canary(&st, &file).await.unwrap_err().to_string();
        assert!(err.contains("different vault"), "{err}");
        assert_eq!(st.get(CANARY_KEY).await.unwrap(), original, "the existing canary must be left alone");
    }

    #[tokio::test]
    async fn missing_or_corrupt_files_are_clear_errors() {
        let (st, dir) = storage();
        assert!(install_canary(&st, &dir.path().join("nope.bin")).await.is_err());

        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, b"not a canary").unwrap();
        assert!(install_canary(&st, &bad).await.unwrap_err().to_string().contains("not a valid canary"));

        let mut trailing = canary_bytes(1);
        trailing.push(0);
        std::fs::write(&bad, trailing).unwrap();
        assert!(install_canary(&st, &bad).await.is_err(), "trailing bytes are rejected");
        assert!(st.get(CANARY_KEY).await.is_err(), "nothing may be stored from a bad file");
    }
}