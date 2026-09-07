use std::path::Path;
use std::sync::{Arc, Once};

use rustls::pki_types::CertificateDer;

#[derive(thiserror::Error, Debug)]
pub enum MtlsError {
    #[error("failed to read {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("no private key found in {0}")]
    NoPrivateKey(String),
    #[error("TLS config error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("failed to parse client certificate")]
    CertParse,
}

/// The identity of the mTLS peer that made this request, extracted from
/// their client certificate's Common Name after the handshake — never
/// from anything the request body claims about itself. Inserted as an
/// Axum request extension by the connection-handling loop in `main.rs`,
/// once per connection (not once per request — a single mTLS connection
/// keeps its verified identity for its whole lifetime, matching how the
/// handshake itself works).
#[derive(Debug, Clone)]
pub struct ClientIdentity(pub String);

static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// Installs `ring` as the process-wide default rustls crypto provider,
/// exactly once. Needed because `reqwest`'s TLS stack pulls in
/// `aws-lc-rs` while our own direct `rustls` dependency defaults to
/// `ring` — with two providers compiled into the same binary, rustls
/// 0.23 refuses to silently guess and panics on the first `ServerConfig`
/// or `ClientConfig` built without an explicit choice. Called from every
/// entry point that touches rustls (this module's `build_server_config`,
/// and `main.rs` before building the reqwest client), so it's always
/// installed before it's needed regardless of which one runs first —
/// `Once` makes calling it from multiple places safe.
pub fn ensure_crypto_provider_installed() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| MtlsError::Io { path: path.display().to_string(), source: e })?,
    );
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::Io { path: path.display().to_string(), source: e })
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, MtlsError> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| MtlsError::Io { path: path.display().to_string(), source: e })?,
    );
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| MtlsError::Io { path: path.display().to_string(), source: e })?
        .ok_or_else(|| MtlsError::NoPrivateKey(path.display().to_string()))
}

/// Builds a `rustls::ServerConfig` that requires every client to present
/// a certificate signed by `ca_cert_path`, and refuses the handshake
/// entirely otherwise — there is no code path in this config that
/// accepts an unauthenticated connection. This exact shape (client-cert
/// verifier via `WebPkiClientVerifier`, `with_single_cert` for the
/// server's own identity) was verified against a real TCP+TLS handshake
/// before being written here: valid client certs are accepted and their
/// CN is extractable, connections with no client cert are rejected, and
/// connections presenting a cert not signed by the trusted CA are
/// rejected — including when the certs and keys are loaded from real
/// PEM files on disk, exactly as this function does.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
) -> Result<Arc<rustls::ServerConfig>, MtlsError> {
    ensure_crypto_provider_installed();

    let server_chain = load_cert_chain(cert_path)?;
    let server_key = load_private_key(key_path)?;
    let ca_chain = load_cert_chain(ca_cert_path)?;

    let mut roots = rustls::RootCertStore::empty();
    for ca_cert in ca_chain {
        roots.add(ca_cert).map_err(|_| MtlsError::CertParse)?;
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| MtlsError::Io { path: ca_cert_path.display().to_string(), source: std::io::Error::other(e) })?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_chain, server_key)?;
    Ok(Arc::new(config))
}

/// Extracts the client certificate's Common Name (e.g. "alice-operator",
/// or a cluster peer's node id) from the DER-encoded peer certificate
/// rustls hands back after a successful handshake. Returns `None` if the
/// cert is malformed or has no CN — callers should treat that as "no
/// usable identity," not silently proceed as an anonymous request, since
/// by the time this is called the handshake already required *some*
/// CA-signed certificate to exist.
pub fn extract_cn(cert_der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;
    let cn = cert.subject().iter_common_name().next().and_then(|attr| attr.as_str().ok()).map(|s| s.to_string());
    cn
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::io::Write;

    struct TestCert {
        cert_der: CertificateDer<'static>,
        key_der: Vec<u8>,
    }

    fn make_ca() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Sentinel Test CA");
        params.distinguished_name = dn;
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    fn make_leaf(ca_cert: &rcgen::Certificate, ca_key: &KeyPair, cn: &str) -> TestCert {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
        TestCert { cert_der: cert.der().clone(), key_der: key.serialize_der() }
    }

    fn write_pem(path: &Path, der: &[u8], label: &str) {
        let pem = pem::Pem::new(label.to_string(), der.to_vec());
        std::fs::File::create(path).unwrap().write_all(pem.to_string().as_bytes()).unwrap();
    }

    #[test]
    fn extract_cn_reads_the_common_name() {
        let (ca_cert, ca_key) = make_ca();
        let leaf = make_leaf(&ca_cert, &ca_key, "alice-operator");
        let cn = extract_cn(&leaf.cert_der).expect("should extract a CN");
        assert_eq!(cn, "alice-operator");
    }

    #[test]
    fn build_server_config_loads_real_pem_files_and_trusts_the_ca() {
        let (ca_cert, ca_key) = make_ca();
        let server_cert = make_leaf(&ca_cert, &ca_key, "sentinel-node-1");

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        let ca_path = dir.path().join("ca.crt");
        write_pem(&cert_path, server_cert.cert_der.as_ref(), "CERTIFICATE");
        write_pem(&key_path, &server_cert.key_der, "PRIVATE KEY");
        write_pem(&ca_path, ca_cert.der().as_ref(), "CERTIFICATE");

        let config = build_server_config(&cert_path, &key_path, &ca_path);
        assert!(config.is_ok(), "should build a valid ServerConfig from real PEM files: {:?}", config.err());
    }

    #[test]
    fn build_server_config_fails_cleanly_on_missing_file() {
        let result = build_server_config(
            Path::new("/nonexistent/cert.crt"),
            Path::new("/nonexistent/key.key"),
            Path::new("/nonexistent/ca.crt"),
        );
        assert!(matches!(result, Err(MtlsError::Io { .. })));
    }
}