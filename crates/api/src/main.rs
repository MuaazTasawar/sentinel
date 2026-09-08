mod config;
mod errors;
mod handlers;
mod middleware;
mod routes;
mod state;
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

    let storage = Arc::new(sentinel_storage::SledStorage::open(&cfg.storage_path)?);
    let audit = Arc::new(tokio::sync::Mutex::new(sentinel_audit::AuditChain::new()));
    // Sealed at startup, always — nothing in this bootstrap path ever
    // populates the KEK. Unsealing is an explicit, separate operation
    // (Phase 4's hardware-quorum flow) that a future phase wires to an
    // admin-only endpoint or local socket; a node that can unseal itself
    // just by starting up would defeat the entire point of the quorum.
    let kek = Arc::new(tokio::sync::Mutex::new(None));

    let peer_addrs = cfg.parse_peer_addrs()?;
    let peer_ids: Vec<u64> = peer_addrs.keys().copied().collect();

    let http_client = build_mtls_reqwest_client(&cfg)?;
    let raft_transport = Arc::new(HttpTransport::new(http_client, peer_addrs));

    let raft = sentinel_consensus::spawn_raft_actor(
        cfg.node_id,
        peer_ids,
        raft_transport,
        Duration::from_millis(50),
        sentinel_consensus::ElectionTimeoutRange::default(),
    );

    // 1 bucket/second, 60-second rolling baseline, flag anything more
    // than 3 standard deviations above recent normal traffic. These are
    // reasonable starting defaults, not values proven optimal for any
    // particular deployment's real traffic shape — an operator running
    // this in production should expect to tune bucket width and
    // threshold against their own access patterns before trusting it to
    // seal automatically.
    let anomaly_detector = Arc::new(tokio::sync::Mutex::new(sentinel_anomaly::AnomalyDetector::new(
        Duration::from_secs(1),
        60,
        3.0,
    )));

    let app_state = AppState { storage, raft, audit, kek, anomaly_detector };
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
/// client — cluster RPCs are not a trusted-by-default side channel).
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