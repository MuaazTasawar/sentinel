//! Unseal / seal endpoints.
//!
//! The quorum lives **on the node**: each key holder decrypts their own
//! Shamir share locally (on their YubiKey, via `sentinel-cli`) and submits
//! just that one share over mTLS. The node accumulates shares in an
//! in-memory session, reconstructs the key once the threshold is met, and
//! only accepts it if it opens the vault's stored *canary* (see
//! `sentinel_crypto::canary`). No single request ever carries the whole
//! key, and a wrong or partial set of shares is rejected rather than
//! silently "unsealing" with garbage.
//!
//! First-unseal caveat (documented, not hidden): if a vault has no canary
//! yet *and* no stored secrets, the first successful reconstruction defines
//! the canary (trust-on-first-use). That is harmless for an empty vault
//! but means a wrong first quorum would lock in a wrong key; Phase 17's
//! `sentinel-cli init` removes this by creating the canary at provisioning.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use bincode::Options;
use sentinel_crypto::canary;
use sentinel_crypto::envelope::{EnvelopeCiphertext, KEY_LEN};
use sentinel_crypto::shamir::ShamirShare;
use sentinel_crypto::SecretBytes;
use sentinel_hardware::{HardwareError, QuorumUnseal, UnsealFragment};
use sentinel_storage::StorageError;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::middleware::mtls::ClientIdentity;
use crate::state::AppState;

/// Storage key for the KEK canary. Deliberately outside `secrets/` so it
/// never appears in `GET /secrets`.
pub const CANARY_KEY: &str = "sys/kek-canary";

/// How long a half-finished unseal session survives. Stops a stray or
/// hostile partial submission from blocking holders indefinitely.
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bounds on untrusted input, checked before any decoding.
const MAX_SHARE_HEX_LEN: usize = 2048;
const MAX_SHARE_BYTES: u64 = 1024;
const MAX_HOLDER_ID_LEN: usize = 64;

struct Session {
    quorum: QuorumUnseal,
    started: Option<Instant>,
}

#[derive(Clone)]
pub struct UnsealState {
    threshold: u8,
    session_timeout: Duration,
    session: Arc<Mutex<Session>>,
}

impl UnsealState {
    pub fn new(threshold: u8) -> Self {
        Self::with_timeout(threshold, DEFAULT_SESSION_TIMEOUT)
    }

    pub fn with_timeout(threshold: u8, session_timeout: Duration) -> Self {
        Self {
            threshold,
            session_timeout,
            session: Arc::new(Mutex::new(Session { quorum: QuorumUnseal::new(threshold), started: None })),
        }
    }

    fn fresh_session(&self) -> Session {
        Session { quorum: QuorumUnseal::new(self.threshold), started: None }
    }
}

#[derive(Deserialize)]
pub struct SubmitShare {
    /// Human label for the key holder ("alice-yubikey"); used for the
    /// duplicate-holder rule and the audit log only.
    pub holder_id: String,
    /// Hex of the bincode-encoded `ShamirShare` this holder decrypted.
    pub share: String,
}

/// Accepts one key holder's share. Returns `{"status":"pending",...}`
/// until the threshold is reached, then `{"status":"unsealed"}`.
pub async fn submit_share(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Json(req): Json<SubmitShare>,
) -> Result<Json<Value>, AppError> {
    if state.kek.lock().await.is_some() {
        return Err(AppError::Conflict("vault is already unsealed".into()));
    }
    validate_holder_id(&req.holder_id)?;
    let share = decode_share(&req.share)?;

    let mut session = state.unseal.session.lock().await;
    if let Some(started) = session.started {
        if started.elapsed() > state.unseal.session_timeout {
            *session = state.unseal.fresh_session();
            state.audit.lock().await.append("unseal session expired; discarded partial shares");
        }
    }

    session
        .quorum
        .contribute(UnsealFragment { holder_id: req.holder_id.clone(), share })
        .map_err(|e| match e {
            HardwareError::DuplicateHolder(h) => {
                AppError::Conflict(format!("holder {h:?} already contributed to this unseal session"))
            }
            other => AppError::BadRequest(other.to_string()),
        })?;
    session.started.get_or_insert_with(Instant::now);

    state.audit.lock().await.append(format!(
        "unseal share accepted from holder {} (submitted by {}) [{}/{}]",
        req.holder_id,
        identity.0,
        session.quorum.contributed_so_far(),
        state.unseal.threshold
    ));

    if !session.quorum.is_satisfied() {
        return Ok(Json(json!({
            "status": "pending",
            "contributed": session.quorum.contributed_so_far(),
            "threshold": state.unseal.threshold,
        })));
    }

    // Threshold reached: whatever happens next, this session is finished.
    let reconstructed = session.quorum.try_reconstruct();
    *session = state.unseal.fresh_session();
    drop(session);

    let bytes = reconstructed.map_err(|e| AppError::BadRequest(e.to_string()))?;
    let kek = SecretBytes::new(bytes);

    if let Err(e) = verify_or_initialise_canary(&state, &kek).await {
        state.audit.lock().await.append(format!("UNSEAL FAILED (quorum submitted by {}): {e}", identity.0));
        return Err(e);
    }

    *state.kek.lock().await = Some(kek);
    state.audit.lock().await.append(format!("vault UNSEALED (quorum completed by {})", identity.0));
    Ok(Json(json!({ "status": "unsealed" })))
}

/// Discards any partially collected shares (e.g. after a mistaken or
/// hostile submission) so the key holders can start over.
pub async fn reset_session(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
) -> StatusCode {
    *state.unseal.session.lock().await = state.unseal.fresh_session();
    state.audit.lock().await.append(format!("unseal session reset by {}", identity.0));
    StatusCode::NO_CONTENT
}

/// Manually seals the node: drops the in-memory KEK and any partial unseal
/// session. Idempotent.
pub async fn seal(State(state): State<AppState>, Extension(identity): Extension<ClientIdentity>) -> StatusCode {
    *state.kek.lock().await = None;
    *state.unseal.session.lock().await = state.unseal.fresh_session();
    state.audit.lock().await.append(format!("vault SEALED manually by {}", identity.0));
    StatusCode::NO_CONTENT
}

async fn verify_or_initialise_canary(state: &AppState, kek: &SecretBytes) -> Result<(), AppError> {
    if kek.len() != KEY_LEN {
        return Err(AppError::BadRequest(
            "the submitted shares did not reconstruct a valid vault key".into(),
        ));
    }

    match state.storage.get(CANARY_KEY).await {
        Ok(blob) => {
            let canary_blob: EnvelopeCiphertext =
                bincode::deserialize(&blob).map_err(|e| AppError::Internal(anyhow::anyhow!("corrupt key canary: {e}")))?;
            if canary::verify(kek, &canary_blob) {
                Ok(())
            } else {
                Err(AppError::BadRequest(
                    "the submitted shares did not reconstruct the vault's key (wrong shares, wrong holders, or too few)".into(),
                ))
            }
        }
        Err(StorageError::NotFound(_)) => {
            if !state.allow_canary_bootstrap {
                // The safe default. Letting the first quorum define the canary
                // would bless whatever key a (possibly mistaken or malicious)
                // first quorum produced. A real vault is provisioned instead.
                return Err(AppError::Conflict(
                    "this vault has not been initialised: no key canary is installed. Run `sentinel-cli init`, set `canary_file` to the canary.bin it wrote, and restart the node (development only: `allow_canary_bootstrap = true`)".into(),
                ));
            }
            // Development bootstrap. Only safe if the vault is empty:
            // otherwise we'd be blessing an unverified key over real data.
            if !state.storage.list("secrets/").await?.is_empty() {
                return Err(AppError::Conflict(
                    "vault holds secrets but has no key canary; refusing to unseal (possible tampering or data loss)".into(),
                ));
            }
            let canary_blob = canary::create(kek)?;
            let bytes = bincode::serialize(&canary_blob).map_err(|e| AppError::Internal(e.into()))?;
            state.storage.put(CANARY_KEY, bytes).await?;
            state.audit.lock().await.append("vault key canary initialised (first unseal of an empty vault)");
            Ok(())
        }
        Err(other) => Err(other.into()),
    }
}

fn validate_holder_id(id: &str) -> Result<(), AppError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_HOLDER_ID_LEN
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "holder_id must be 1-64 characters of letters, digits, '-', '_' or '.'".into(),
        ))
    }
}

fn decode_share(hex: &str) -> Result<ShamirShare, AppError> {
    let bad = || AppError::BadRequest("share must be the hex encoding of a Shamir share".into());
    if hex.len() > MAX_SHARE_HEX_LEN {
        return Err(bad());
    }
    let bytes = decode_hex(hex).ok_or_else(bad)?;
    // Same wire format as `bincode::deserialize`, but with a hard size cap
    // so a hostile length prefix can't make us allocate gigabytes.
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_SHARE_BYTES)
        .deserialize::<ShamirShare>(&bytes)
        .map_err(|_| bad())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::{default_detector, state_with};
    use axum::routing::post;
    use axum::Router;
    use rand::rngs::OsRng;
    use sentinel_crypto::shamir;
    use tower::ServiceExt;

    const KEK_BYTES: [u8; KEY_LEN] = [0x42u8; KEY_LEN];

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/sys/unseal", post(submit_share).delete(reset_session))
            .route("/sys/seal", post(seal))
            .layer(Extension(ClientIdentity("admin".to_string())))
            .with_state(state)
    }

    fn shares_for(secret: &[u8]) -> Vec<String> {
        shamir::split_secret(secret, 2, 3, &mut OsRng)
            .unwrap()
            .iter()
            .map(|s| to_hex(&bincode::serialize(s).unwrap()))
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    async fn submit(router: &Router, holder: &str, share: &str) -> (StatusCode, Value) {
        let body = json!({ "holder_id": holder, "share": share }).to_string();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/sys/unseal")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post_empty(router: &Router, uri: &str) -> StatusCode {
        let req = axum::http::Request::builder().method("POST").uri(uri).body(axum::body::Body::empty()).unwrap();
        router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_quorum_of_shares_unseals_a_fresh_vault_and_creates_the_canary() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let kek = state.kek.clone();
        let storage = state.storage.clone();
        let audit = state.audit.clone();
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        let (status, body) = submit(&router, "alice", &shares[0]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "pending");
        assert_eq!(body["contributed"], 1);
        assert_eq!(body["threshold"], 2);
        assert!(kek.lock().await.is_none(), "one share must not unseal a 2-of-3 vault");

        let (status, body) = submit(&router, "bob", &shares[2]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "unsealed");
        assert_eq!(kek.lock().await.as_ref().unwrap().expose(), &KEK_BYTES);

        assert!(storage.get(CANARY_KEY).await.is_ok(), "first unseal must persist the canary");
        let chain = audit.lock().await;
        assert!(chain.verify().is_ok());
        let events: Vec<&str> = chain.entries().iter().map(|e| e.event.as_str()).collect();
        assert!(events.iter().any(|e| e.starts_with("vault UNSEALED")));
        assert!(events.iter().any(|e| e.starts_with("unseal share accepted from holder alice")));
    }

    #[tokio::test]
    async fn without_a_provisioned_canary_the_first_unseal_is_refused_by_default() {
        let (mut state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        state.allow_canary_bootstrap = false;
        let kek = state.kek.clone();
        let storage = state.storage.clone();
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        submit(&router, "alice", &shares[0]).await;
        let (status, body) = submit(&router, "bob", &shares[1]).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].as_str().unwrap().contains("sentinel-cli init"), "the error must say what to do: {body}");
        assert!(kek.lock().await.is_none(), "an unprovisioned vault must stay sealed");
        assert!(storage.get(CANARY_KEY).await.is_err(), "and must not invent a canary");
    }

    #[tokio::test]
    async fn a_provisioned_canary_makes_trust_on_first_use_unnecessary_and_still_rejects_wrong_keys() {
        let (mut state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        state.allow_canary_bootstrap = false;
        // What `sentinel-cli init` + the node's startup installer put in storage.
        let canary_blob = canary::create(&SecretBytes::new(KEK_BYTES.to_vec())).unwrap();
        state.storage.put(CANARY_KEY, bincode::serialize(&canary_blob).unwrap()).await.unwrap();
        let kek = state.kek.clone();
        let router = app(state);

        // Wrong quorum first: refused.
        let wrong = shares_for(&[0x99u8; KEY_LEN]);
        submit(&router, "alice", &wrong[0]).await;
        let (status, _) = submit(&router, "bob", &wrong[1]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(kek.lock().await.is_none());

        // Right quorum: unsealed.
        let good = shares_for(&KEK_BYTES);
        submit(&router, "alice", &good[0]).await;
        let (status, body) = submit(&router, "bob", &good[2]).await;
        assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("unsealed")));
    }

    #[tokio::test]
    async fn the_wrong_key_is_rejected_once_a_canary_exists() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let kek = state.kek.clone();
        let audit = state.audit.clone();
        let router = app(state);

        // Initialise the vault with the real key, then seal it again.
        let good = shares_for(&KEK_BYTES);
        submit(&router, "alice", &good[0]).await;
        submit(&router, "bob", &good[1]).await;
        assert!(kek.lock().await.is_some());
        assert_eq!(post_empty(&router, "/sys/seal").await, StatusCode::NO_CONTENT);
        assert!(kek.lock().await.is_none());

        // A quorum for a *different* key must be refused, and the vault stay sealed.
        let wrong = shares_for(&[0x99u8; KEY_LEN]);
        submit(&router, "alice", &wrong[0]).await;
        let (status, body) = submit(&router, "bob", &wrong[1]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("did not reconstruct"));
        assert!(kek.lock().await.is_none(), "a wrong key must never be accepted");
        assert!(audit.lock().await.entries().iter().any(|e| e.event.starts_with("UNSEAL FAILED")));

        // The failed attempt resets the session; the right quorum still works.
        submit(&router, "alice", &good[0]).await;
        let (status, body) = submit(&router, "bob", &good[2]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "unsealed");
    }

    #[tokio::test]
    async fn the_same_holder_cannot_submit_twice() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let kek = state.kek.clone();
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        submit(&router, "alice", &shares[0]).await;
        let (status, _) = submit(&router, "alice", &shares[1]).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(kek.lock().await.is_none());
    }

    #[tokio::test]
    async fn submitting_while_already_unsealed_is_a_conflict() {
        let (state, _dir) = crate::state::test_support::unsealed_state().await;
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);
        let (status, _) = submit(&router, "alice", &shares[0]).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn malformed_input_is_a_400_not_a_panic() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let router = app(state);

        for bad in ["", "zz", "abc", "00", &"ab".repeat(5000)] {
            let (status, _) = submit(&router, "alice", bad).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "share {bad:.10?} should be rejected");
        }
        // A hostile bincode length prefix claiming a huge Vec must hit the size cap.
        let hostile = to_hex(&[1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
        let (status, _) = submit(&router, "alice", &hostile).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let shares = shares_for(&KEK_BYTES);
        for bad_id in ["", "has space", "semi;colon", &"a".repeat(65), "new\nline"] {
            let (status, _) = submit(&router, bad_id, &shares[0]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "holder id {bad_id:?} should be rejected");
        }
    }

    #[tokio::test]
    async fn an_expired_partial_session_is_discarded() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::with_timeout(2, Duration::from_millis(30))).await;
        let kek = state.kek.clone();
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        submit(&router, "alice", &shares[0]).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let (status, body) = submit(&router, "bob", &shares[1]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "pending", "alice's stale share must have been dropped");
        assert!(kek.lock().await.is_none());
    }

    #[tokio::test]
    async fn reset_clears_a_partial_session() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        submit(&router, "alice", &shares[0]).await;
        let req = axum::http::Request::builder().method("DELETE").uri("/sys/unseal").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

        let (_, body) = submit(&router, "alice", &shares[0]).await;
        assert_eq!(body["contributed"], 1, "after a reset alice may contribute again");
    }

    #[tokio::test]
    async fn refuses_to_define_a_canary_over_existing_secrets() {
        let (state, _dir) = state_with(None, default_detector(), UnsealState::new(2)).await;
        let kek = state.kek.clone();
        // Simulate a vault with data but a missing canary.
        state.storage.put("secrets/precious", vec![1, 2, 3]).await.unwrap();
        let router = app(state);
        let shares = shares_for(&KEK_BYTES);

        submit(&router, "alice", &shares[0]).await;
        let (status, body) = submit(&router, "bob", &shares[1]).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].as_str().unwrap().contains("no key canary"));
        assert!(kek.lock().await.is_none());
    }

    #[tokio::test]
    async fn manual_seal_drops_the_key_and_is_audited() {
        let (state, _dir) = crate::state::test_support::unsealed_state().await;
        let kek = state.kek.clone();
        let audit = state.audit.clone();
        let router = app(state);

        assert_eq!(post_empty(&router, "/sys/seal").await, StatusCode::NO_CONTENT);
        assert!(kek.lock().await.is_none());
        assert!(audit.lock().await.entries().iter().any(|e| e.event == "vault SEALED manually by admin"));
        // Idempotent.
        assert_eq!(post_empty(&router, "/sys/seal").await, StatusCode::NO_CONTENT);
    }
}