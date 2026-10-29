mod bootstrap;
mod config;
mod errors;
mod handlers;
mod middleware;
mod routes;
mod state;
mod statemachine;
mod transport;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use config::NodeConfig;
use middleware::mtls::{self, ClientIdentity};
use state::AppState;
use transport::HttpTransport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    mtls::ensure_crypto_provider_installed();

    let cfg = NodeConfig::load()?;
    tracing::info!(node_id = cfg.node_id, "sentinel node starting");

    let storage: Arc<dyn sentinel_storage::Storage> = Arc::new(sentinel_storage::SledStorage::open(&cfg.storage_path)?);
    if let Some(canary_file) = &cfg.canary_file {
        match bootstrap::install_canary(&*storage, std::path::Path::new(canary_file)).await? {
            bootstrap::CanaryOutcome::Installed => tracing::info!("installed the vault key canary from {canary_file}"),
            bootstrap::CanaryOutcome::AlreadyPresent => tracing::info!("vault key canary already installed"),
        }
    }
    if cfg.allow_canary_bootstrap {
        tracing::warn!("allow_canary_bootstrap is ON: the first unseal of an empty vault will define its key canary (trust on first use). Development only.");
    }
    // The audit chain is durable: entries are appended to a file as they happen
    // and the existing file is verified before anything else runs. A log that
    // fails verification is refused, never quietly replaced.
    let audit_path = cfg.audit_path();
    let (mut chain, recovered_torn_tail) = sentinel_audit::open_persistent(&audit_path).map_err(|e| {
        anyhow::anyhow!(
            "the audit log {} failed to open or verify: {e}. Refusing to start. Investigate, and move the file aside only once you have preserved it as evidence",
            audit_path.display()
        )
    })?;
    if recovered_torn_tail {
        tracing::warn!("the audit log ended in an incomplete record (a crash mid-write); it was discarded");
        chain.append("audit log recovery: an incomplete final record from an earlier crash was discarded");
    }
    chain.append(format!("node {} started (audit log: {} entries before this one)", cfg.node_id, chain.entries().len()));
    let audit = Arc::new(tokio::sync::Mutex::new(chain));
    // Sealed at startup, always: nothing in this bootstrap path ever
    // populates the KEK. A node that could unseal itself just by starting
    // up would defeat the entire point of the quorum. Unsealing is an
    // explicit operation: key holders submit their shares to
    // `POST /sys/unseal` (see `sentinel-cli unseal`).
    let kek = Arc::new(tokio::sync::Mutex::new(None));
    if cfg.unseal_threshold < 2 {
        anyhow::bail!("unseal_threshold must be at least 2 (got {}); a threshold of 1 is not a quorum", cfg.unseal_threshold);
    }

    let peer_addrs = cfg.parse_peer_addrs()?;

    // Authorization is default-deny. A policy that would lock everyone out (no
    // admins, no secret clients, peers without peer identities) is a startup
    // error rather than a vault nobody can use, and the insecure development
    // switch is refused unless explicitly set.
    let policy = middleware::authz::Policy::new(&cfg.policy_config(), !peer_addrs.is_empty())
        .map_err(|e| anyhow::anyhow!("invalid authorization configuration: {e}"))?;
    for warning in policy.warnings() {
        tracing::warn!("{warning}");
    }
    let policy = Arc::new(policy);
    let peer_ids: Vec<u64> = peer_addrs.keys().copied().collect();

    let http_client = build_mtls_reqwest_client(&cfg)?;
    // One object plays two roles: the Raft RPC transport, and the way this
    // node asks the leader to seal the cluster when it is not the leader.
    let peer_transport = Arc::new(HttpTransport::new(http_client, peer_addrs));
    let raft_transport: Arc<dyn sentinel_consensus::Transport> = peer_transport.clone();
    let seal_forwarder: Arc<dyn transport::SealForwarder> = peer_transport;

    // Raft's term, vote and log live on disk and are fsync'd before this node
    // answers a peer or acknowledges a client, so a crash or restart cannot
    // make it forget a vote or lose an entry it already confirmed.
    let raft_dir = cfg.raft_dir();
    let raft_store = sentinel_consensus::FileStore::open(&raft_dir)?;
    let (raft, committed) = sentinel_consensus::spawn_raft_actor_persistent(
        cfg.node_id,
        peer_ids,
        raft_transport,
        Duration::from_millis(50),
        sentinel_consensus::ElectionTimeoutRange::default(),
        Box::new(raft_store),
    )?;
    tracing::info!(dir = %raft_dir.display(), "raft state loaded");

    // The only code path that changes the secret store: committed log entries.
    let applied = statemachine::spawn_apply_loop(committed, storage.clone(), kek.clone(), audit.clone());

    // 1 bucket/second, 60-second rolling baseline, flag anything more
    // than 3 standard deviations above recent normal traffic. These are
    // reasonable starting defaults, not values proven optimal for any
    // particular deployment's real traffic shape - an operator running
    // this in production should expect to tune bucket width and
    // threshold against their own access patterns before trusting it to
    // seal automatically.
    let anomaly_detector = Arc::new(tokio::sync::Mutex::new(sentinel_anomaly::AnomalyDetector::new(
        Duration::from_secs(1),
        60,
        3.0,
    )));

    let unseal = handlers::unseal::UnsealState::new(cfg.unseal_threshold);
    let app_state = AppState {
        storage,
        raft,
        audit,
        kek,
        anomaly_detector,
        unseal,
        applied,
        commit_timeout: Duration::from_millis(cfg.commit_timeout_ms),
        policy: policy.clone(),
        seal_forwarder,
        allow_canary_bootstrap: cfg.allow_canary_bootstrap,
    };
    let router = routes::build_router(app_state);

    let tls_config = mtls::build_server_config(
        std::path::Path::new(&cfg.tls_cert_path),
        std::path::Path::new(&cfg.tls_key_path),
        std::path::Path::new(&cfg.ca_cert_path),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(&cfg.api_bind_addr).await?;
    tracing::info!(addr = %cfg.api_bind_addr, "listening for mTLS connections");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        let policy = policy.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(peer = %peer_addr, error = %e, "mTLS handshake failed");
                    return;
                }
            };

            let identity = {
                let (_, conn) = tls_stream.get_ref();
                conn.peer_certificates()
                    .and_then(|certs| certs.first())
                    .and_then(mtls::extract_cn)
                    .map(ClientIdentity)
            };
            let Some(identity) = identity else {
                tracing::warn!(peer = %peer_addr, "handshake succeeded but client cert had no readable CN; refusing connection");
                return;
            };

            // Revocation: refuse a certificate whose serial is on the deny-list,
            // even though the CA signed it and the handshake succeeded.
            let serial = {
                let (_, conn) = tls_stream.get_ref();
                conn.peer_certificates().and_then(|certs| certs.first()).and_then(mtls::cert_serial_hex)
            };
            if let Some(serial) = &serial {
                if policy.is_revoked(serial) {
                    tracing::warn!(peer = %peer_addr, identity = %identity.0, serial = %serial, "refusing a connection from a revoked certificate");
                    return;
                }
            }

            let router_with_identity = router.layer(axum::Extension(identity));
            let hyper_service = hyper_util::service::TowerToHyperService::new(router_with_identity);

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                .await
            {
                tracing::warn!(peer = %peer_addr, error = %e, "connection ended with error");
            }
        });
    }
}

/// Builds the `reqwest::Client` this node uses to call peers, presenting
/// this node's own cert/key as its client identity (peer nodes verify it
/// exactly the same way the API's own mTLS listener verifies any other
/// client - cluster RPCs are not a trusted-by-default side channel).
fn build_mtls_reqwest_client(cfg: &NodeConfig) -> anyhow::Result<reqwest::Client> {
    let mut identity_pem = std::fs::read(&cfg.tls_cert_path)?;
    identity_pem.extend_from_slice(&std::fs::read(&cfg.tls_key_path)?);
    let identity = reqwest::Identity::from_pem(&identity_pem)?;
    let ca_pem = std::fs::read(&cfg.ca_cert_path)?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)?;

    Ok(reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .use_rustls_tls()
        .timeout(Duration::from_secs(5))
        .build()?)
}