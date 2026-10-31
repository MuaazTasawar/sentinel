//! Authorization: who may do what.
//!
//! mTLS proves *who* is calling (the Common Name of a certificate our CA
//! signed). It says nothing about what they may do. Before this module any
//! client with any valid certificate could call every route, including the
//! cluster-internal `/raft/*` endpoints and the seal/unseal controls. That is
//! replaced by an explicit, default-deny role policy:
//!
//! | role   | may do                                              |
//! |--------|-----------------------------------------------------|
//! | peer   | the cluster-internal `/raft/*` RPCs, and nothing else |
//! | admin  | `/sys/*` (unseal, seal, reset the unseal session)     |
//! | writer | write/delete secrets, and everything a reader can     |
//! | reader | read/list secrets, view the dashboard and status      |
//!
//! Roles are deliberately separate. A compromised node certificate cannot read
//! secrets; an unsealing operator cannot read them either (separation of
//! duties); a plain application client cannot touch the cluster protocol.
//!
//! Trust model for peers: Raft tolerates crashed nodes, not malicious ones.
//! Anyone holding a `peer_cns` certificate is fully trusted by the cluster.
//!
//! Revocation: this is a deny-list of certificate serial numbers checked right
//! after the TLS handshake. It is not CRL/OCSP; revoking means editing config
//! and restarting the node.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::middleware::mtls::ClientIdentity;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Raft RPCs between cluster nodes.
    ClusterRpc,
    /// Unseal, seal, reset the unseal session.
    Admin,
    ReadSecrets,
    WriteSecrets,
    /// Dashboard, `/api/status`, `/cluster/status`.
    ViewStatus,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PolicyError {
    #[error("no admin_cns configured: nobody would be able to unseal the vault (list at least one identity)")]
    NoAdmins,
    #[error("neither reader_cns nor writer_cns is configured: nobody could ever read or write a secret")]
    NoSecretClients,
    #[error("peers are configured but peer_cns is empty: the cluster's own nodes would be refused")]
    NoPeerIdentities,
    #[error("identity {0:?} is listed as a peer and also as an admin/reader/writer; node certificates must not double as client identities")]
    PeerIsAlsoClient(String),
    #[error("invalid identity {0:?}: must be 1-128 characters with no control characters")]
    BadIdentity(String),
    #[error("invalid certificate serial {0:?}: expected hexadecimal digits (colons and a 0x prefix are allowed)")]
    BadSerial(String),
}

/// Raw lists as they appear in configuration.
#[derive(Debug, Clone, Default)]
pub struct PolicyConfig {
    pub peer_cns: Vec<String>,
    pub admin_cns: Vec<String>,
    pub writer_cns: Vec<String>,
    pub reader_cns: Vec<String>,
    pub revoked_serials: Vec<String>,
    /// DEVELOPMENT ONLY. Restores the old behaviour: every client with a valid
    /// certificate may do everything, including cluster RPCs.
    pub insecure_allow_any_client: bool,
}

/// How long a repeated denial for the same identity+permission stays out of
/// the audit chain. (Every denial is still logged via `tracing`; the audit
/// chain lives in memory, so a client hammering a forbidden route must not be
/// able to grow it without bound.)
const DENIAL_AUDIT_WINDOW: Duration = Duration::from_secs(60);

pub struct Policy {
    peers: HashSet<String>,
    admins: HashSet<String>,
    writers: HashSet<String>,
    readers: HashSet<String>,
    revoked: HashSet<String>,
    allow_any: bool,
    warnings: Vec<String>,
    last_denial_audit: Mutex<HashMap<(String, Permission), Instant>>,
}

fn clean_identities(list: &[String]) -> Result<HashSet<String>, PolicyError> {
    let mut out = HashSet::new();
    for raw in list {
        let cn = raw.trim();
        if cn.is_empty() || cn.len() > 128 || cn.chars().any(|c| c.is_control()) {
            return Err(PolicyError::BadIdentity(raw.clone()));
        }
        out.insert(cn.to_string());
    }
    Ok(out)
}

/// Canonical form for comparing serials: lowercase hex, no `0x`, no colons, no
/// leading zeros (`"00:AB"` and `"0xab"` both become `"ab"`).
pub fn normalize_serial(raw: &str) -> Option<String> {
    let s = raw.trim().trim_start_matches("0x").trim_start_matches("0X").replace(':', "");
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let trimmed = s.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() })
}

impl Policy {
    /// Builds and validates a policy. `has_peers` says whether this node is
    /// configured with any cluster peers.
    pub fn new(cfg: &PolicyConfig, has_peers: bool) -> Result<Self, PolicyError> {
        let peers = clean_identities(&cfg.peer_cns)?;
        let admins = clean_identities(&cfg.admin_cns)?;
        let writers = clean_identities(&cfg.writer_cns)?;
        let readers = clean_identities(&cfg.reader_cns)?;
        let mut revoked = HashSet::new();
        for raw in &cfg.revoked_serials {
            revoked.insert(normalize_serial(raw).ok_or_else(|| PolicyError::BadSerial(raw.clone()))?);
        }

        let mut warnings = Vec::new();
        if cfg.insecure_allow_any_client {
            warnings.push(
                "insecure_allow_any_client is ON: every client with a valid certificate may call every route, including /raft/* and /sys/*. Never use this in production.".to_string(),
            );
        } else {
            if admins.is_empty() {
                return Err(PolicyError::NoAdmins);
            }
            if readers.is_empty() && writers.is_empty() {
                return Err(PolicyError::NoSecretClients);
            }
            if has_peers && peers.is_empty() {
                return Err(PolicyError::NoPeerIdentities);
            }
            for p in &peers {
                if admins.contains(p) || writers.contains(p) || readers.contains(p) {
                    return Err(PolicyError::PeerIsAlsoClient(p.clone()));
                }
            }
            for a in &admins {
                if writers.contains(a) || readers.contains(a) {
                    warnings.push(format!(
                        "identity {a:?} is both an admin and a secret reader/writer; separation of duties is lost for it"
                    ));
                }
            }
        }

        Ok(Self { peers, admins, writers, readers, revoked, allow_any: cfg.insecure_allow_any_client, warnings, last_denial_audit: Mutex::new(HashMap::new()) })
    }

    /// A policy that permits everything. Test fixtures only; production code
    /// reaches the same behaviour solely through the explicit, loudly warned
    /// `insecure_allow_any_client` setting.
    #[cfg(test)]
    pub fn allow_any() -> Self {
        Self::new(&PolicyConfig { insecure_allow_any_client: true, ..Default::default() }, false).expect("always valid")
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn allows(&self, cn: &str, permission: Permission) -> bool {
        if self.allow_any {
            return true;
        }
        match permission {
            Permission::ClusterRpc => self.peers.contains(cn),
            Permission::Admin => self.admins.contains(cn),
            Permission::ReadSecrets => self.readers.contains(cn) || self.writers.contains(cn),
            Permission::WriteSecrets => self.writers.contains(cn),
            Permission::ViewStatus => self.admins.contains(cn) || self.readers.contains(cn) || self.writers.contains(cn),
        }
    }

    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        normalize_serial(serial_hex).map(|s| self.revoked.contains(&s)).unwrap_or(false)
    }

    /// True if this denial should be written to the audit chain (the first one
    /// per identity+permission per window).
    fn should_audit_denial(&self, cn: &str, permission: Permission, now: Instant) -> bool {
        let mut seen = self.last_denial_audit.lock().unwrap();
        if seen.len() > 10_000 {
            seen.retain(|_, t| now.duration_since(*t) < DENIAL_AUDIT_WINDOW);
        }
        let key = (cn.to_string(), permission);
        match seen.get(&key) {
            Some(last) if now.duration_since(*last) < DENIAL_AUDIT_WINDOW => false,
            _ => {
                seen.insert(key, now);
                true
            }
        }
    }
}

async fn enforce(state: AppState, permission: Permission, req: Request, next: Next) -> Response {
    let cn = req.extensions().get::<ClientIdentity>().map(|i| i.0.clone());

    if let Some(cn) = &cn
        && state.policy.allows(cn, permission) {
            return next.run(req).await;
        }

    let who = cn.unwrap_or_else(|| "<no identity>".to_string());
    let what = format!("{} {}", req.method(), req.uri().path());
    tracing::warn!(identity = %who, request = %what, required = ?permission, "access denied by policy");
    if state.policy.should_audit_denial(&who, permission, Instant::now()) {
        state.audit.lock().await.append(format!("ACCESS DENIED: {who} attempted {what} (requires {permission:?})"));
    }
    (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden: this identity is not permitted to perform this operation" }))).into_response()
}

pub async fn require_cluster_rpc(State(s): State<AppState>, req: Request, next: Next) -> Response {
    enforce(s, Permission::ClusterRpc, req, next).await
}
pub async fn require_admin(State(s): State<AppState>, req: Request, next: Next) -> Response {
    enforce(s, Permission::Admin, req, next).await
}
pub async fn require_read(State(s): State<AppState>, req: Request, next: Next) -> Response {
    enforce(s, Permission::ReadSecrets, req, next).await
}
pub async fn require_write(State(s): State<AppState>, req: Request, next: Next) -> Response {
    enforce(s, Permission::WriteSecrets, req, next).await
}
pub async fn require_view(State(s): State<AppState>, req: Request, next: Next) -> Response {
    enforce(s, Permission::ViewStatus, req, next).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn standard() -> PolicyConfig {
        PolicyConfig {
            peer_cns: list(&["node1", "node2"]),
            admin_cns: list(&["root"]),
            writer_cns: list(&["app-w"]),
            reader_cns: list(&["app-r"]),
            ..Default::default()
        }
    }

    #[test]
    fn each_role_gets_exactly_its_permissions() {
        let p = Policy::new(&standard(), true).unwrap();
        use Permission::*;
        let all = [ClusterRpc, Admin, ReadSecrets, WriteSecrets, ViewStatus];
        let expect = |cn: &str, allowed: &[Permission]| {
            for perm in all {
                assert_eq!(p.allows(cn, perm), allowed.contains(&perm), "{cn} / {perm:?}");
            }
        };
        expect("node1", &[ClusterRpc]);
        expect("root", &[Admin, ViewStatus]);
        expect("app-r", &[ReadSecrets, ViewStatus]);
        expect("app-w", &[ReadSecrets, WriteSecrets, ViewStatus]);
        expect("stranger", &[]);
        expect("", &[]);
    }

    #[test]
    fn identity_matching_is_exact_not_substring_or_case_insensitive() {
        let p = Policy::new(&standard(), true).unwrap();
        for cn in ["node", "node11", "NODE1", "node1 ", "xnode1", "root\0"] {
            assert!(!p.allows(cn, Permission::ClusterRpc), "{cn:?}");
        }
    }

    #[test]
    fn the_insecure_switch_permits_everything_and_says_so() {
        let p = Policy::new(&PolicyConfig { insecure_allow_any_client: true, ..Default::default() }, true).unwrap();
        assert!(p.allows("anyone", Permission::ClusterRpc) && p.allows("anyone", Permission::Admin));
        assert!(p.warnings().iter().any(|w| w.contains("insecure_allow_any_client")));
    }

    #[test]
    fn a_policy_that_would_lock_everyone_out_is_refused_at_startup() {
        let mut c = standard();
        c.admin_cns.clear();
        assert_eq!(Policy::new(&c, true).err(), Some(PolicyError::NoAdmins));

        let mut c = standard();
        c.writer_cns.clear();
        c.reader_cns.clear();
        assert_eq!(Policy::new(&c, true).err(), Some(PolicyError::NoSecretClients));

        let mut c = standard();
        c.peer_cns.clear();
        assert_eq!(Policy::new(&c, true).err(), Some(PolicyError::NoPeerIdentities));
        assert!(Policy::new(&c, false).is_ok(), "a single node needs no peer identities");
    }

    #[test]
    fn a_node_certificate_cannot_also_be_a_client() {
        let mut c = standard();
        c.reader_cns.push("node1".into());
        assert_eq!(Policy::new(&c, true).err(), Some(PolicyError::PeerIsAlsoClient("node1".into())));
    }

    #[test]
    fn an_admin_who_is_also_a_secret_client_is_allowed_but_warned_about() {
        let mut c = standard();
        c.reader_cns.push("root".into());
        let p = Policy::new(&c, true).unwrap();
        assert!(p.warnings().iter().any(|w| w.contains("root") && w.contains("separation of duties")));
    }

    #[test]
    fn blank_overlong_or_control_character_identities_are_rejected() {
        for bad in ["", "   ", &"a".repeat(129), "bad\nname"] {
            let mut c = standard();
            c.admin_cns.push(bad.to_string());
            assert!(matches!(Policy::new(&c, true), Err(PolicyError::BadIdentity(_))), "{bad:?}");
        }
    }

    #[test]
    fn serials_are_normalised_so_formatting_cannot_dodge_the_deny_list() {
        assert_eq!(normalize_serial("00:AB:cd").as_deref(), Some("abcd"));
        assert_eq!(normalize_serial("0xABCD").as_deref(), Some("abcd"));
        assert_eq!(normalize_serial("0").as_deref(), Some("0"));
        assert_eq!(normalize_serial("0000").as_deref(), Some("0"));
        assert_eq!(normalize_serial("xyz"), None);
        assert_eq!(normalize_serial(""), None);

        let mut c = standard();
        c.revoked_serials = list(&["0x00AB:CD"]);
        let p = Policy::new(&c, true).unwrap();
        assert!(p.is_revoked("abcd") && p.is_revoked("AB:CD") && p.is_revoked("00abcd"));
        assert!(!p.is_revoked("abce") && !p.is_revoked("not hex"));

        let mut c = standard();
        c.revoked_serials = list(&["zz"]);
        assert!(matches!(Policy::new(&c, true), Err(PolicyError::BadSerial(_))));
    }

    #[test]
    fn repeated_denials_are_audited_once_per_window_per_identity_and_permission() {
        let p = Policy::new(&standard(), true).unwrap();
        let t0 = Instant::now();
        assert!(p.should_audit_denial("mallory", Permission::Admin, t0));
        assert!(!p.should_audit_denial("mallory", Permission::Admin, t0 + Duration::from_secs(1)));
        assert!(p.should_audit_denial("mallory", Permission::ClusterRpc, t0), "a different permission is a new event");
        assert!(p.should_audit_denial("eve", Permission::Admin, t0), "a different identity is a new event");
        assert!(p.should_audit_denial("mallory", Permission::Admin, t0 + DENIAL_AUDIT_WINDOW + Duration::from_secs(1)));
    }
}