use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use sentinel_consensus::ConsensusError;
use sentinel_crypto::envelope;

use crate::errors::AppError;
use crate::state::AppState;

fn storage_key(key: &str) -> String {
    format!("secrets/{key}")
}

/// Writes a secret. Requires the vault to be unsealed and this node to
/// be the current Raft leader — the write is proposed to the log before
/// it's applied to storage, so a write that succeeds has at least been
/// accepted into the leader's log (not yet proof of majority
/// replication, which is why this stays a documented simplification
/// rather than a claimed guarantee — see the note below).
pub async fn put_secret(
    State(state): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let kek_guard = state.kek.lock().await;
    let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;
    let ciphertext = envelope::encrypt(kek, &body)?;
    drop(kek_guard);

    let serialized = bincode::serialize(&ciphertext).map_err(|e| AppError::Internal(e.into()))?;

    // NOTE ON SEQUENCING (intentional simplification, not an oversight):
    // a fully correct Raft-backed vault applies a write to storage only
    // once its log index is confirmed committed (replicated to a
    // majority), via an "apply loop" that watches commit_index and
    // applies entries in order. That apply loop doesn't exist yet — this
    // skeleton proposes the write (which fails closed with NotLeader if
    // this node isn't the leader, so at least only a leader can write)
    // and then applies it directly. That means a leader that's about to
    // lose an election (e.g. it's partitioned and hasn't realized it
    // yet) could locally apply a write that never reaches a majority,
    // which a real deployment cannot tolerate. Flagging this precisely
    // because it is the single biggest gap between "looks like Raft" and
    // "is linearizable" in the current codebase.
    state.raft.propose(serialized.clone()).await.map_err(|e| match e {
        ConsensusError::NotLeader => AppError::NotLeader(None),
        other => AppError::Internal(other.into()),
    })?;

    state.storage.put(&storage_key(&key), serialized).await?;

    state.audit.lock().await.append(format!("secret written: {key}"));

    Ok(StatusCode::OK)
}

/// Reads a secret. Requires the vault to be unsealed. Does not require
/// leadership — reads are served locally, which is standard practice
/// for a "read your own writes isn't guaranteed on a stale follower"
/// tradeoff; a future phase could add a leader-only strict-read mode for
/// callers that need linearizable reads.
pub async fn get_secret(State(state): State<AppState>, Path(key): Path<String>) -> Result<Bytes, AppError> {
    let kek_guard = state.kek.lock().await;
    let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;

    let blob = state.storage.get(&storage_key(&key)).await.map_err(|_| AppError::NotFound)?;
    let ciphertext: envelope::EnvelopeCiphertext =
        bincode::deserialize(&blob).map_err(|e| AppError::Internal(e.into()))?;
    let plaintext = envelope::decrypt(kek, &ciphertext)?;
    drop(kek_guard);

    state.audit.lock().await.append(format!("secret read: {key}"));

    Ok(Bytes::from(plaintext))
}

/// Deletes a secret. Same leadership requirement and the same
/// propose-then-apply simplification as `put_secret`.
pub async fn delete_secret(State(state): State<AppState>, Path(key): Path<String>) -> Result<StatusCode, AppError> {
    let command = format!("delete:{key}").into_bytes();
    state.raft.propose(command).await.map_err(|e| match e {
        ConsensusError::NotLeader => AppError::NotLeader(None),
        other => AppError::Internal(other.into()),
    })?;

    state.storage.delete(&storage_key(&key)).await?;
    state.audit.lock().await.append(format!("secret deleted: {key}"));

    Ok(StatusCode::NO_CONTENT)
}

/// Lists secret keys under an optional prefix (the storage layer already
/// namespaces everything under `secrets/`, so callers see plain key
/// names without that prefix).
pub async fn list_secrets(State(state): State<AppState>) -> Result<axum::Json<Vec<String>>, AppError> {
    let full_keys = state.storage.list("secrets/").await?;
    let keys = full_keys.into_iter().map(|k| k.trim_start_matches("secrets/").to_string()).collect();
    Ok(axum::Json(keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use sentinel_consensus::spawn_raft_actor;
    use sentinel_crypto::envelope::KEY_LEN;
    use sentinel_storage::SledStorage;
    use std::sync::Arc;
    use tower::ServiceExt;

    struct NoopTransport;
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

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let raft = spawn_raft_actor(
            1,
            vec![], // no peers -> becomes its own leader immediately (Phase 6 fix)
            Arc::new(NoopTransport),
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        // Give the single-node election time to complete.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let state = AppState {
            storage,
            raft,
            audit: Arc::new(tokio::sync::Mutex::new(sentinel_audit::AuditChain::new())),
            kek: Arc::new(tokio::sync::Mutex::new(Some(kek))),
        };
        (state, dir)
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/secrets/{key}", get(get_secret).put(put_secret).delete(delete_secret))
            .route("/secrets", get(list_secrets))
            .with_state(state)
    }

    #[tokio::test]
    async fn write_then_read_round_trips_through_encryption() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/db-password")
            .body(axum::body::Body::from("hunter2"))
            .unwrap();
        let put_resp = router.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
        let get_resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"hunter2");
    }

    #[tokio::test]
    async fn read_missing_key_returns_404() {
        let (state, _dir) = test_state().await;
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets/nope").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn read_while_sealed_returns_503() {
        let (state, _dir) = test_state().await;
        *state.kek.lock().await = None; // reseal
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets/anything").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn write_then_delete_then_read_returns_404() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/temp")
            .body(axum::body::Body::from("gone-soon"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        let del_req = axum::http::Request::builder().method("DELETE").uri("/secrets/temp").body(axum::body::Body::empty()).unwrap();
        let del_resp = router.clone().oneshot(del_req).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        let get_req = axum::http::Request::builder().uri("/secrets/temp").body(axum::body::Body::empty()).unwrap();
        let get_resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_returns_written_keys_without_the_storage_prefix() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        for key in ["alpha", "beta"] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/secrets/{key}"))
                .body(axum::body::Body::from("x"))
                .unwrap();
            router.clone().oneshot(req).await.unwrap();
        }

        let list_req = axum::http::Request::builder().uri("/secrets").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(list_req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let mut keys: Vec<String> = serde_json::from_slice(&body).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn audit_log_records_every_operation() {
        let (state, _dir) = test_state().await;
        let audit = state.audit.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/k")
            .body(axum::body::Body::from("v"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        let get_req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
        router.oneshot(get_req).await.unwrap();

        let chain = audit.lock().await;
        assert!(chain.verify().is_ok());
        let events: Vec<&str> = chain.entries().iter().map(|e| e.event.as_str()).collect();
        assert!(events.contains(&"secret written: k"));
        assert!(events.contains(&"secret read: k"));
    }
}