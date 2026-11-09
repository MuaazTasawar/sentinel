//! Operations endpoints for load balancers and monitoring: `/healthz`,
//! `/readyz` and `/metrics`.
//!
//! They sit behind the same mTLS listener as everything else, and behind their
//! own role (`monitor_cns`, plus admins): a monitoring system gets exactly
//! these three routes and cannot read a secret or the dashboard.
//!
//! * `/healthz`  is *liveness*: is the node's own machinery responding?
//!   It fails if the Raft actor stops answering, which is the failure class
//!   that an earlier deadlock fell into: a process that is up but stuck.
//! * `/readyz`   is *readiness*: should this node be sent client traffic?
//!   It fails while the vault is sealed, while the audit log cannot be
//!   written (the node refuses secret operations then), and while Raft is
//!   unresponsive. It does **not** prove that the cluster currently has a
//!   leader: a node does not know that. Writes sent to a follower still get 421.
//! * `/metrics`  is Prometheus text exposition (format 0.0.4). Every value is
//!   a number; the only label is the build version. Nothing in it comes from a
//!   client, so it cannot reveal an identity or a secret name.

use std::fmt::Display;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sentinel_consensus::Role;
use serde_json::json;

use crate::metrics::Metrics;
use crate::state::AppState;

/// How long to wait for the Raft actor before calling it unresponsive.
const RAFT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Asks the Raft actor for its state, or `None` if it does not answer.
///
/// The question is asked on its own task because `RaftHandle::inspect` panics
/// if the actor has already ended. A health endpoint must report that, not
/// crash on it.
async fn probe_raft(state: &AppState) -> Option<(Role, u64, u64)> {
    let raft = state.raft.clone();
    let mut task = tokio::spawn(async move { raft.inspect().await });
    match tokio::time::timeout(RAFT_PROBE_TIMEOUT, &mut task).await {
        Ok(Ok(snapshot)) => Some(snapshot),
        Ok(Err(_)) => None, // the task panicked: the actor is gone
        Err(_) => {
            task.abort(); // no answer in time: do not leave the question parked
            None
        }
    }
}

pub async fn healthz(State(state): State<AppState>) -> Response {
    match probe_raft(&state).await {
        Some(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unhealthy",
                "reason": "the Raft actor is not responding",
            })),
        )
            .into_response(),
    }
}

pub async fn readyz(State(state): State<AppState>) -> Response {
    let mut reasons: Vec<&str> = Vec::new();
    if state.kek.lock().await.is_none() {
        reasons.push("the vault is sealed");
    }
    if !state.audit.lock().await.is_healthy() {
        reasons.push("the audit log cannot be written");
    }
    let raft = probe_raft(&state).await;
    if raft.is_none() {
        reasons.push("the Raft actor is not responding");
    }

    match (reasons.is_empty(), raft) {
        (true, Some((role, _, _))) => (
            StatusCode::OK,
            Json(json!({ "ready": true, "role": format!("{role:?}") })),
        )
            .into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ready": false, "reasons": reasons })),
        )
            .into_response(),
    }
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: impl Display) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    let mut out = String::new();

    out.push_str(&format!(
        "# HELP sentinel_build_info The version of this node.\n# TYPE sentinel_build_info gauge\nsentinel_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    let sealed = state.kek.lock().await.is_none();
    metric(
        &mut out,
        "sentinel_sealed",
        "gauge",
        "1 if the vault is sealed on this node, 0 if unsealed.",
        u8::from(sealed),
    );

    {
        let audit = state.audit.lock().await;
        metric(
            &mut out,
            "sentinel_audit_healthy",
            "gauge",
            "1 if the audit log can be written, 0 if it is degraded (secret operations are refused).",
            u8::from(audit.is_healthy()),
        );
        metric(
            &mut out,
            "sentinel_audit_entries",
            "gauge",
            "Entries in this node's audit chain.",
            audit.entries().len(),
        );
    }

    let raft = probe_raft(&state).await;
    metric(
        &mut out,
        "sentinel_raft_responsive",
        "gauge",
        "1 if the Raft actor answered within the probe timeout.",
        u8::from(raft.is_some()),
    );
    if let Some((role, term, commit_index)) = raft {
        metric(
            &mut out,
            "sentinel_raft_is_leader",
            "gauge",
            "1 if this node is the Raft leader.",
            u8::from(role == Role::Leader),
        );
        metric(
            &mut out,
            "sentinel_raft_term",
            "gauge",
            "The node's current Raft term.",
            term,
        );
        metric(
            &mut out,
            "sentinel_raft_commit_index",
            "gauge",
            "Highest Raft log index known to be committed.",
            commit_index,
        );
        metric(
            &mut out,
            "sentinel_raft_applied_index",
            "gauge",
            "Highest Raft log index applied to this node's storage.",
            *state.applied.borrow(),
        );
    }

    let m = &state.metrics;
    for (name, help, counter) in [
        (
            "sentinel_secret_reads_total",
            "Secrets returned to clients.",
            &m.secret_reads,
        ),
        (
            "sentinel_secret_writes_total",
            "Secret writes acknowledged after a majority commit.",
            &m.secret_writes,
        ),
        (
            "sentinel_secret_deletes_total",
            "Secret deletions acknowledged after a majority commit.",
            &m.secret_deletes,
        ),
        (
            "sentinel_authz_denials_total",
            "Requests refused by the authorization policy.",
            &m.authz_denials,
        ),
        (
            "sentinel_auto_seals_total",
            "Times this node sealed itself on anomalous read traffic.",
            &m.auto_seals,
        ),
        (
            "sentinel_unseals_total",
            "Successful quorum unseals.",
            &m.unseals,
        ),
        (
            "sentinel_unseal_failures_total",
            "Completed quorums that did not rebuild the vault's key.",
            &m.unseal_failures,
        ),
    ] {
        metric(&mut out, name, "counter", help, Metrics::get(counter));
    }

    let mut response = out.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::{sealed_state, unsealed_state};
    use axum::Router;
    use axum::routing::get;
    use serde_json::Value;
    use tower::ServiceExt;

    fn router(state: AppState) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics))
            .with_state(state)
    }

    async fn fetch(router: &Router, uri: &str) -> (StatusCode, String, Option<String>) {
        let req = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            String::from_utf8_lossy(&body).into_owned(),
            content_type,
        )
    }

    fn json_of(body: &str) -> Value {
        serde_json::from_str(body).expect("a JSON body")
    }

    /// The value of an unlabelled sample line `name <value>`.
    fn sample(text: &str, name: &str) -> Option<f64> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} ")))
            .map(|v| v.parse().expect("a numeric sample"))
    }

    #[tokio::test]
    async fn a_sealed_node_is_alive_but_not_ready() {
        let (state, _dir) = sealed_state().await;
        let r = router(state);

        let (status, body, _) = fetch(&r, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body)["status"], "ok");

        let (status, body, _) = fetch(&r, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let v = json_of(&body);
        assert_eq!(v["ready"], false);
        assert!(
            v["reasons"].to_string().contains("sealed"),
            "the reason must say why: {v}"
        );
    }

    #[tokio::test]
    async fn an_unsealed_healthy_node_is_ready() {
        let (state, _dir) = unsealed_state().await;
        let (status, body, _) = fetch(&router(state), "/readyz").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let v = json_of(&body);
        assert_eq!(v["ready"], true);
        assert_eq!(v["role"], "Leader");
    }

    #[tokio::test]
    async fn a_dead_raft_actor_is_reported_not_panicked_on() {
        let (state, _dir) = unsealed_state().await;
        state.raft.shutdown().await;
        // Give the actor task a moment to end.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = router(state);

        let (status, body, _) = fetch(&r, "/healthz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(json_of(&body)["status"], "unhealthy");

        let (status, body, _) = fetch(&r, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(json_of(&body)["reasons"].to_string().contains("Raft"));

        let (status, text, _) = fetch(&r, "/metrics").await;
        assert_eq!(status, StatusCode::OK, "metrics must still answer");
        assert_eq!(sample(&text, "sentinel_raft_responsive"), Some(0.0));
        assert_eq!(
            sample(&text, "sentinel_raft_term"),
            None,
            "no Raft numbers are invented for a dead actor"
        );
    }

    #[tokio::test]
    async fn metrics_are_valid_prometheus_text_describing_the_node() {
        let (state, _dir) = sealed_state().await;
        let (status, text, content_type) = fetch(&router(state), "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type.as_deref(),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );

        // Every line is a comment or `name[{labels}] number`.
        for line in text.lines() {
            if line.starts_with('#') {
                assert!(
                    line.starts_with("# HELP ") || line.starts_with("# TYPE "),
                    "bad comment line: {line}"
                );
                continue;
            }
            let (name_part, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("bad sample line: {line}"));
            let name = name_part.split('{').next().unwrap();
            assert!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
                    && !name.starts_with(|c: char| c.is_ascii_digit()),
                "bad metric name in: {line}"
            );
            value
                .parse::<f64>()
                .unwrap_or_else(|_| panic!("non-numeric value in: {line}"));
        }

        assert_eq!(sample(&text, "sentinel_sealed"), Some(1.0));
        assert_eq!(sample(&text, "sentinel_audit_healthy"), Some(1.0));
        assert_eq!(sample(&text, "sentinel_raft_responsive"), Some(1.0));
        assert_eq!(sample(&text, "sentinel_raft_is_leader"), Some(1.0));
        assert!(sample(&text, "sentinel_raft_term").unwrap() >= 1.0);
        for counter in [
            "sentinel_secret_reads_total",
            "sentinel_secret_writes_total",
            "sentinel_secret_deletes_total",
            "sentinel_authz_denials_total",
            "sentinel_auto_seals_total",
            "sentinel_unseals_total",
            "sentinel_unseal_failures_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {counter} counter")),
                "{counter} must be declared as a counter"
            );
            assert_eq!(
                sample(&text, counter),
                Some(0.0),
                "{counter} starts at zero"
            );
        }

        let (state, _dir) = unsealed_state().await;
        let (_, text, _) = fetch(&router(state), "/metrics").await;
        assert_eq!(sample(&text, "sentinel_sealed"), Some(0.0));
    }
}
