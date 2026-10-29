use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Extension;
use std::time::Instant;

use crate::middleware::mtls::ClientIdentity;

use sentinel_crypto::envelope;

use crate::errors::AppError;
use crate::state::AppState;
use crate::statemachine::{storage_key, Command};

const MAX_KEY_LEN: usize = 512;

/// Secret names end up in storage keys and the audit log, so keep them sane.
fn validate_key(key: &str) -> Result<(), AppError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN || key.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "secret names must be 1-{MAX_KEY_LEN} bytes with no control characters"
        )));
    }
    Ok(())
}

/// Secret operations are refused while the audit log cannot be written: no
/// secret is read, written, deleted or listed without a durable record. (At
/// most the single operation in flight when the disk first failed can complete
/// unrecorded; everything after it is refused. Sealing is never blocked.)
async fn require_audit_healthy(state: &AppState) -> Result<(), AppError> {
    if state.audit.lock().await.is_healthy() {
        Ok(())
    } else {
        Err(AppError::AuditUnavailable)
    }
}

/// Proposes `command` and returns only once a **majority of the cluster has
/// committed it** and this node's state machine has applied it. Handlers never
/// write storage themselves, so a 2xx from here means the change is durable on
/// a majority, not just accepted by a leader that might be about to lose its
/// majority.
async fn commit(state: &AppState, command: Command) -> Result<(), AppError> {
    let index = state.raft.propose_and_wait(command.encode(), state.commit_timeout).await?;

    let mut applied = state.applied.clone();
    match tokio::time::timeout(state.commit_timeout, applied.wait_for(|&v| v >= index)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(AppError::CommitTimeout),
    }
}

/// Every operation that touches the secret store, including listing and
/// deleting, must refuse while sealed. A sealed vault is supposed to be
/// inert: it must not reveal which keys exist, nor accept destructive
/// operations, until a quorum has unsealed it.
async fn require_unsealed(state: &AppState) -> Result<(), AppError> {
    if state.kek.lock().await.is_none() {
        Err(AppError::Sealed)
    } else {
        Ok(())
    }
}

/// Writes a secret. Requires the vault to be unsealed and this node to be
/// the Raft leader. The value is encrypted here, the ciphertext is proposed
/// to the log, and the call returns only after a majority has committed it
/// and this node has applied it (see [`commit`]). On a follower it fails
/// with 421 (`NotLeader`); if the leader cannot reach a majority it fails
/// with 504 and **nothing is written**.
pub async fn put_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_audit_healthy(&state).await?;
    validate_key(&key)?;

    let kek_guard = state.kek.lock().await;
    let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;
    let ciphertext = envelope::encrypt(kek, &body)?;
    drop(kek_guard);

    let value = bincode::serialize(&ciphertext).map_err(|e| AppError::Internal(e.into()))?;
    commit(&state, Command::Put { key: key.clone(), value }).await?;

    state.audit.lock().await.append(format!("secret written: {key} (by {})", identity.0));

    Ok(StatusCode::OK)
}

/// Reads a secret. Requires the vault to be unsealed. Does not require
/// leadership: reads are served from this node's own storage, so a follower
/// that is a moment behind the leader can briefly return an older value.
///
/// Every **successful** read is recorded against the node's anomaly detector.
/// If the resulting access rate is a statistical outlier against this node's
/// own recent baseline, the vault seals itself, withholds the secret it was
/// about to return, and asks the cluster to seal too (see [`propagate_seal`]).
///
/// Only reads that actually return a secret count. Lookups of names that do
/// not exist (404), reads against a sealed vault (503) and failed decryptions
/// reveal nothing, so they must not be able to trip the seal: otherwise any
/// client with a valid certificate could lock the whole vault by looping over
/// made-up names. Such misses are not an exfiltration signal.
pub async fn get_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
) -> Result<Bytes, AppError> {
    require_audit_healthy(&state).await?;
    let plaintext = {
        let kek_guard = state.kek.lock().await;
        let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;

        let blob = state.storage.get(&storage_key(&key)).await.map_err(|_| AppError::NotFound)?;
        let ciphertext: envelope::EnvelopeCiphertext =
            bincode::deserialize(&blob).map_err(|e| AppError::Internal(e.into()))?;
        envelope::decrypt(kek, &ciphertext)?
    };

    let anomaly = state.anomaly_detector.lock().await.record_access(Instant::now());
    if let Some(report) = anomaly {
        // Seal locally first and unconditionally: a node that detects the
        // anomaly must protect itself even if replication is degraded, which
        // is exactly when it is most likely to be. The plaintext we already
        // decrypted is dropped here, never returned.
        *state.kek.lock().await = None;
        let reason = format!(
            "access rate anomaly detected by {}: count={}, baseline_mean={:.1}, z_score={:.1}",
            identity.0, report.current_count, report.baseline_mean, report.z_score
        );
        state.audit.lock().await.append(format!(
            "AUTO-SEAL triggered by {}: access rate anomaly (count={}, baseline_mean={:.1}, z_score={:.1})",
            identity.0, report.current_count, report.baseline_mean, report.z_score
        ));
        propagate_seal(&state, reason).await;
        return Err(AppError::Sealed);
    }

    state.audit.lock().await.append(format!("secret read: {key} (by {})", identity.0));

    Ok(Bytes::from(plaintext))
}

/// Gets a seal to the rest of the cluster. If this node is the leader the
/// seal is proposed to the log and every node applies it when it commits. If
/// it is not, the request is forwarded to the peers in the background (only
/// the leader accepts it). Either way the caller has already sealed locally.
async fn propagate_seal(state: &AppState, reason: String) {
    let command = Command::Seal { reason: reason.clone() };
    match state.raft.propose(command.encode()).await {
        Ok(_) => {}
        Err(sentinel_consensus::ConsensusError::NotLeader) => {
            let forwarder = state.seal_forwarder.clone();
            tokio::spawn(async move {
                let accepted = forwarder.forward_seal(&reason).await;
                if accepted == 0 {
                    tracing::warn!("no peer accepted the forwarded seal (no leader reachable); only this node is sealed");
                }
            });
        }
        Err(e) => tracing::warn!(error = %e, "could not propose the cluster-wide seal"),
    }
}

/// Deletes a secret. Requires the vault to be unsealed and this node to be
/// the leader, and returns only after a majority has committed the deletion
/// (same contract as [`put_secret`]).
pub async fn delete_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    require_audit_healthy(&state).await?;
    require_unsealed(&state).await?;
    validate_key(&key)?;

    commit(&state, Command::Delete { key: key.clone() }).await?;
    state.audit.lock().await.append(format!("secret deleted: {key} (by {})", identity.0));

    Ok(StatusCode::NO_CONTENT)
}

/// Lists secret keys. Requires the vault to be unsealed. (The storage
/// layer namespaces everything under `secrets/`, so callers see plain key
/// names without that prefix.)
pub async fn list_secrets(State(state): State<AppState>) -> Result<axum::Json<Vec<String>>, AppError> {
    require_audit_healthy(&state).await?;
    require_unsealed(&state).await?;
    let full_keys = state.storage.list("secrets/").await?;
    let keys = full_keys.into_iter().map(|k| k.trim_start_matches("secrets/").to_string()).collect();
    Ok(axum::Json(keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::{sealed_state, state_with, unsealed_state};
    use crate::handlers::unseal::UnsealState;
    use axum::{routing::get, Router};
    use sentinel_crypto::envelope::KEY_LEN;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn test_state() -> (AppState, tempfile::TempDir) {
        unsealed_state().await
    }

    async fn test_state_with_detector(detector: sentinel_anomaly::AnomalyDetector) -> (AppState, tempfile::TempDir) {
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        state_with(Some(kek), detector, UnsealState::new(2)).await
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/secrets/{key}", get(get_secret).put(put_secret).delete(delete_secret))
            .route("/secrets", get(list_secrets))
            .layer(axum::Extension(ClientIdentity("test-client".to_string())))
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
        *state.kek.lock().await = None;
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
        assert!(events.contains(&"secret written: k (by test-client)"));
        assert!(events.contains(&"secret read: k (by test-client)"));
    }

    #[tokio::test]
    async fn sudden_read_burst_triggers_auto_seal_and_is_audit_logged() {
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let audit = state.audit.clone();
        let kek = state.kek.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/db-password")
            .body(axum::body::Body::from("hunter2"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "baseline reads should succeed normally");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut sealed = false;
        for _ in 0..40 {
            let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
                sealed = true;
                break;
            }
        }
        assert!(sealed, "a sudden read burst should trigger auto-seal");
        assert!(kek.lock().await.is_none(), "KEK should be cleared once auto-seal fires");

        let chain = audit.lock().await;
        assert!(chain.verify().is_ok(), "audit chain must remain internally consistent even after an auto-seal event");
        assert!(
            chain.entries().iter().any(|e| e.event.starts_with("AUTO-SEAL triggered")),
            "the seal event itself must be audit-logged, not just silently applied"
        );

        drop(chain);
        let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn list_while_sealed_returns_503() {
        let (state, _dir) = sealed_state().await;
        state.storage.put("secrets/hidden", vec![1]).await.unwrap();
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "a sealed vault must not reveal key names");
    }

    #[tokio::test]
    async fn delete_while_sealed_returns_503_and_leaves_the_secret_intact() {
        let (state, _dir) = test_state().await;
        let kek_handle = state.kek.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder().method("PUT").uri("/secrets/keep-me").body(axum::body::Body::from("v")).unwrap();
        assert_eq!(router.clone().oneshot(put_req).await.unwrap().status(), StatusCode::OK);

        let saved_kek = kek_handle.lock().await.take();
        let del_req = axum::http::Request::builder().method("DELETE").uri("/secrets/keep-me").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.clone().oneshot(del_req).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);

        *kek_handle.lock().await = saved_kek;
        let get_req = axum::http::Request::builder().uri("/secrets/keep-me").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the sealed-state delete must not have removed anything");
    }

    #[tokio::test]
    async fn a_write_on_a_node_that_is_not_leader_is_refused_and_stores_nothing() {
        use crate::state::test_support::{build, default_detector};
        // Peers exist but never answer, so this node can never win an election.
        struct Silent;
        #[async_trait::async_trait]
        impl sentinel_consensus::Transport for Silent {
            async fn send_request_vote(&self, p: u64, _: sentinel_consensus::RequestVoteRequest) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: sentinel_consensus::AppendEntriesRequest) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
        }
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let (state, _dir) = build(Some(kek), default_detector(), UnsealState::new(2), vec![2, 3], std::sync::Arc::new(Silent), std::time::Duration::from_secs(1)).await;
        let storage = state.storage.clone();
        let router = app(state);

        let req = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("v")).unwrap();
        assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::MISDIRECTED_REQUEST);
        assert!(storage.get("secrets/k").await.is_err(), "a refused write must leave no trace");
    }

    #[tokio::test]
    async fn a_leader_that_cannot_reach_a_majority_does_not_apply_the_write() {
        // The bug this phase fixes: the old handler proposed and then wrote
        // straight to storage, so a partitioned leader "succeeded" with data
        // no other node had. Now the write waits for a majority, times out,
        // and storage is untouched.
        use crate::state::test_support::{build, default_detector, VotesButNoReplication};
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let (state, _dir) = build(
            Some(kek),
            default_detector(),
            UnsealState::new(2),
            vec![2, 3],
            std::sync::Arc::new(VotesButNoReplication),
            std::time::Duration::from_millis(400),
        )
        .await;
        // Wait until this node has actually become leader.
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while state.raft.inspect().await.0 != sentinel_consensus::Role::Leader {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("node should win the (fake) election");

        let storage = state.storage.clone();
        let audit = state.audit.clone();
        let router = app(state);

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/orphan").body(axum::body::Body::from("secret")).unwrap();
        let resp = router.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT, "an unconfirmed write must not report success");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(storage.get("secrets/orphan").await.is_err(), "the write must not have reached storage");
        assert!(
            !audit.lock().await.entries().iter().any(|e| e.event.starts_with("secret written: orphan")),
            "and must not be audited as written"
        );

        let del = axum::http::Request::builder().method("DELETE").uri("/secrets/orphan").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.oneshot(del).await.unwrap().status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn bad_secret_names_are_rejected_before_anything_is_proposed() {
        let (state, _dir) = test_state().await;
        let router = app(state);
        let long = "a".repeat(513);
        for name in [long.as_str(), "bad%0Aname", "tab%09name"] {
            let req = axum::http::Request::builder().method("PUT").uri(format!("/secrets/{name}")).body(axum::body::Body::from("v")).unwrap();
            assert_eq!(router.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST, "name {name:.12?}");
        }
    }

    #[tokio::test]
    async fn the_anomaly_seal_is_proposed_as_a_replicated_command_and_applied() {
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let audit = state.audit.clone();
        let router = app(state);

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("v")).unwrap();
        router.clone().oneshot(put).await.unwrap();
        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            router.clone().oneshot(req).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for _ in 0..40 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            if router.clone().oneshot(req).await.unwrap().status() == StatusCode::SERVICE_UNAVAILABLE {
                break;
            }
        }

        // The committed seal command comes back out of the log and is applied.
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if audit.lock().await.entries().iter().any(|e| e.event.contains("committed cluster-wide seal command")) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the replicated seal command should have been applied");
    }

    #[tokio::test]
    async fn lookups_of_names_that_do_not_exist_can_never_trip_the_auto_seal() {
        // The DoS this fixes: any client with a valid certificate could loop
        // over made-up names, the 404s counted as "reads", and the whole
        // vault sealed itself.
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let kek = state.kek.clone();
        let router = app(state);

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/real").body(axum::body::Body::from("v")).unwrap();
        router.clone().oneshot(put).await.unwrap();
        // A normal baseline of successful reads...
        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/real").body(axum::body::Body::empty()).unwrap();
            assert_eq!(router.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // ...then a flood of misses far larger than the burst that DOES seal the vault.
        for i in 0..400 {
            let req = axum::http::Request::builder().uri(format!("/secrets/missing-{i}")).body(axum::body::Body::empty()).unwrap();
            assert_eq!(router.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND, "request {i}");
        }
        assert!(kek.lock().await.is_some(), "a flood of 404s must not seal the vault");

        let req = axum::http::Request::builder().uri("/secrets/real").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::OK, "and the vault still serves real reads");
    }

    #[tokio::test]
    async fn the_secret_that_triggers_the_seal_is_withheld() {
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let router = app(state);
        let put = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("TOP-SECRET")).unwrap();
        router.clone().oneshot(put).await.unwrap();
        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            router.clone().oneshot(req).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut leaked_after_seal = false;
        let mut sealed = false;
        for _ in 0..60 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            if status == StatusCode::SERVICE_UNAVAILABLE {
                sealed = true;
                assert!(!String::from_utf8_lossy(&body).contains("TOP-SECRET"), "the sealing response must not carry the secret");
            } else if sealed {
                leaked_after_seal = true;
            }
        }
        assert!(sealed, "the burst should have sealed the vault");
        assert!(!leaked_after_seal, "once sealed, no later read may succeed");
    }

    #[tokio::test]
    async fn an_anomaly_on_a_follower_is_forwarded_to_the_peers_instead_of_being_dropped() {
        use crate::state::test_support::build;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Silent;
        #[async_trait::async_trait]
        impl sentinel_consensus::Transport for Silent {
            async fn send_request_vote(&self, p: u64, _: sentinel_consensus::RequestVoteRequest) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: sentinel_consensus::AppendEntriesRequest) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
        }
        struct Recorder(Arc<AtomicUsize>, Arc<std::sync::Mutex<String>>);
        #[async_trait::async_trait]
        impl crate::transport::SealForwarder for Recorder {
            async fn forward_seal(&self, reason: &str) -> usize {
                self.0.fetch_add(1, Ordering::SeqCst);
                *self.1.lock().unwrap() = reason.to_string();
                1
            }
        }

        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        // Peers exist but never answer, so this node is permanently a follower.
        let (mut state, _dir) = build(Some(sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN])), detector, UnsealState::new(2), vec![2, 3], Arc::new(Silent), std::time::Duration::from_secs(1)).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let reason = Arc::new(std::sync::Mutex::new(String::new()));
        state.seal_forwarder = Arc::new(Recorder(calls.clone(), reason.clone()));

        // A follower cannot take writes through Raft, so place the ciphertext directly.
        let blob = bincode::serialize(&envelope::encrypt(&kek, b"v").unwrap()).unwrap();
        state.storage.put("secrets/k", blob).await.unwrap();
        let kek_handle = state.kek.clone();
        let router = app(state);

        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            router.clone().oneshot(req).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for _ in 0..60 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            if router.clone().oneshot(req).await.unwrap().status() == StatusCode::SERVICE_UNAVAILABLE {
                break;
            }
        }
        assert!(kek_handle.lock().await.is_none(), "the follower seals itself immediately");

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the seal should have been forwarded to the peers");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "forwarded exactly once");
        assert!(reason.lock().unwrap().contains("access rate anomaly"));
    }

    /// A sink that always fails, standing in for a full or failed disk.
    #[derive(Debug)]
    struct DeadDisk;
    impl sentinel_audit::AuditSink for DeadDisk {
        fn persist(&mut self, _: &sentinel_audit::AuditEntry) -> Result<(), sentinel_audit::AuditError> {
            Err(sentinel_audit::AuditError::Io("disk full".into()))
        }
    }

    #[tokio::test]
    async fn when_the_audit_log_cannot_be_written_secret_operations_are_refused() {
        let (state, _dir) = test_state().await;
        let router = app(state.clone());

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("v")).unwrap();
        assert_eq!(router.clone().oneshot(put).await.unwrap().status(), StatusCode::OK, "healthy: works");

        // The disk fails: the very next audit write is lost and the chain degrades.
        *state.audit.lock().await = sentinel_audit::AuditChain::with_sink(vec![], Box::new(DeadDisk)).unwrap();
        state.audit.lock().await.append("this entry cannot be saved");
        assert!(!state.audit.lock().await.is_healthy());

        for (method, uri, body) in [("GET", "/secrets/k", ""), ("PUT", "/secrets/k2", "v"), ("DELETE", "/secrets/k", ""), ("GET", "/secrets", "")] {
            let req = axum::http::Request::builder().method(method).uri(uri).body(axum::body::Body::from(body)).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{method} {uri} must be refused without a durable audit record");
        }
        assert!(state.storage.get("secrets/k2").await.is_err(), "the refused write must not have happened");
        assert!(state.kek.lock().await.is_some(), "refusing is not the same as sealing");
    }
}