use std::path::Path;
use std::sync::{Arc, Once};

use rustls::pki_types::pem as pki_pem;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(thiserror::Error, Debug)]
pub enum MtlsError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("no private key found in {0}")]
    NoPrivateKey(String),
    #[error("TLS config error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("failed to parse client certificate")]
    CertParse,
}

/// The identity of the mTLS peer that made this request, extracted from
/// their client certificate's Common Name after the handshake - never
/// from anything the request body claims about itself. Inserted as an
/// Axum request extension by the connection-handling loop in `main.rs`,
/// once per connection (not once per request - a single mTLS connection
/// keeps its verified identity for its whole lifetime, matching how the
/// handshake itself works).
#[derive(Debug, Clone)]
pub struct ClientIdentity(pub String);

static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// Installs `ring` as the process-wide default rustls crypto provider,
/// exactly once. Needed because `reqwest`'s TLS stack pulls in
/// `aws-lc-rs` while our own direct `rustls` dependency defaults to
/// `ring` - with two providers compiled into the same binary, rustls
/// 0.23 refuses to silently guess and panics on the first `ServerConfig`
/// or `ClientConfig` built without an explicit choice. Called from every
/// entry point that touches rustls (this module's `build_server_config`,
/// and `main.rs` before building the reqwest client), so it's always
/// installed before it's needed regardless of which one runs first -
/// `Once` makes calling it from multiple places safe.
pub fn ensure_crypto_provider_installed() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// PEM parsing errors are mostly not I/O errors, but `MtlsError` reports file
/// problems as I/O; keep the real I/O error when there is one and describe the
/// rest as invalid data.
fn pem_io_error(e: pki_pem::Error) -> std::io::Error {
    match e {
        pki_pem::Error::Io(e) => e,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
    }
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let mut reader =
        std::io::BufReader::new(std::fs::File::open(path).map_err(|e| MtlsError::Io {
            path: path.display().to_string(),
            source: e,
        })?);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::Io {
            path: path.display().to_string(),
            source: pem_io_error(e),
        })
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, MtlsError> {
    let mut reader =
        std::io::BufReader::new(std::fs::File::open(path).map_err(|e| MtlsError::Io {
            path: path.display().to_string(),
            source: e,
        })?);
    // The first private key in the file, in any of the usual formats (PKCS#8,
    // PKCS#1, SEC1); other PEM sections, such as certificates, are skipped.
    match PrivateKeyDer::from_pem_reader(&mut reader) {
        Ok(key) => Ok(key),
        Err(pki_pem::Error::NoItemsFound) => {
            Err(MtlsError::NoPrivateKey(path.display().to_string()))
        }
        Err(e) => Err(MtlsError::Io {
            path: path.display().to_string(),
            source: pem_io_error(e),
        }),
    }
}

/// Builds a `rustls::ServerConfig` that requires every client to present
/// a certificate signed by `ca_cert_path`, and refuses the handshake
/// entirely otherwise - there is no code path in this config that
/// accepts an unauthenticated connection. This exact shape (client-cert
/// verifier via `WebPkiClientVerifier`, `with_single_cert` for the
/// server's own identity) was verified against a real TCP+TLS handshake
/// before being written here: valid client certs are accepted and their
/// CN is extractable, connections with no client cert are rejected, and
/// connections presenting a cert not signed by the trusted CA are
/// rejected - including when the certs and keys are loaded from real
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
        .map_err(|e| MtlsError::Io {
            path: ca_cert_path.display().to_string(),
            source: std::io::Error::other(e),
        })?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_chain, server_key)?;
    Ok(Arc::new(config))
}

/// Extracts the client certificate's Common Name (e.g. "alice-operator",
/// or a cluster peer's node id) from the DER-encoded peer certificate
/// rustls hands back after a successful handshake. Returns `None` if the
/// cert is malformed or has no CN - callers should treat that as "no
/// usable identity," not silently proceed as an anonymous request, since
/// by the time this is called the handshake already required *some*
/// CA-signed certificate to exist.
pub fn extract_cn(cert_der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;

    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
}

/// The certificate's serial number as canonical lowercase hex (no leading
/// zeros), the form the revocation deny-list is compared in.
pub fn cert_serial_hex(cert_der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;
    Some(cert.tbs_certificate.serial.to_str_radix(16))
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
        TestCert {
            cert_der: cert.der().clone(),
            key_der: key.serialize_der(),
        }
    }

    fn write_pem(path: &Path, der: &[u8], label: &str) {
        let pem = pem::Pem::new(label.to_string(), der.to_vec());
        std::fs::File::create(path)
            .unwrap()
            .write_all(pem.to_string().as_bytes())
            .unwrap();
    }

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sentinel-mtls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn a_pem_file_with_several_certificates_loads_all_of_them_in_order() {
        let (ca_cert, ca_key) = make_ca();
        let a = make_leaf(&ca_cert, &ca_key, "first");
        let b = make_leaf(&ca_cert, &ca_key, "second");
        let pem_of = |c: &TestCert| {
            pem::Pem::new("CERTIFICATE".to_string(), c.cert_der.to_vec()).to_string()
        };
        let path = temp_file("chain.pem", &format!("{}{}", pem_of(&a), pem_of(&b)));
        let chain = load_cert_chain(&path).expect("two certificates");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], a.cert_der);
        assert_eq!(chain[1], b.cert_der);
    }

    #[test]
    fn a_file_with_no_private_key_in_it_is_reported_as_such() {
        let (ca_cert, ca_key) = make_ca();
        let a = make_leaf(&ca_cert, &ca_key, "a");
        // A certificate is valid PEM but not a key.
        let path = temp_file(
            "not-a-key.pem",
            &pem::Pem::new("CERTIFICATE".to_string(), a.cert_der.to_vec()).to_string(),
        );
        assert!(matches!(
            load_private_key(&path),
            Err(MtlsError::NoPrivateKey(_))
        ));
        let empty = temp_file("empty.pem", "");
        assert!(matches!(
            load_private_key(&empty),
            Err(MtlsError::NoPrivateKey(_))
        ));
    }

    #[test]
    fn a_private_key_is_loaded_in_the_format_the_pki_tool_writes() {
        let (ca_cert, ca_key) = make_ca();
        let a = make_leaf(&ca_cert, &ca_key, "a");
        let path = temp_file(
            "key.pem",
            &pem::Pem::new("PRIVATE KEY".to_string(), a.key_der.clone()).to_string(),
        );
        match load_private_key(&path).expect("a PKCS#8 key") {
            PrivateKeyDer::Pkcs8(k) => assert_eq!(k.secret_pkcs8_der(), a.key_der.as_slice()),
            other => panic!("expected PKCS#8, got {other:?}"),
        }
    }

    #[test]
    fn garbage_in_a_pem_file_is_an_error_and_never_a_panic() {
        let bad = temp_file(
            "bad.pem",
            "-----BEGIN CERTIFICATE-----\n!!!this is not base64!!!\n-----END CERTIFICATE-----\n",
        );
        assert!(matches!(load_cert_chain(&bad), Err(MtlsError::Io { .. })));
        let truncated = temp_file("truncated.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n");
        assert!(matches!(
            load_private_key(&truncated),
            Err(MtlsError::Io { .. })
        ));
    }

    #[test]
    fn extract_cn_reads_the_common_name() {
        let (ca_cert, ca_key) = make_ca();
        let leaf = make_leaf(&ca_cert, &ca_key, "alice-operator");
        let cn = extract_cn(&leaf.cert_der).expect("should extract a CN");
        assert_eq!(cn, "alice-operator");
    }

    #[test]
    fn the_serial_is_extracted_and_is_stable_and_distinct_per_certificate() {
        let (ca_cert, ca_key) = make_ca();
        let a = make_leaf(&ca_cert, &ca_key, "a");
        let b = make_leaf(&ca_cert, &ca_key, "b");
        let sa = cert_serial_hex(&a.cert_der).expect("serial");
        assert_eq!(sa, cert_serial_hex(&a.cert_der).unwrap());
        assert_ne!(
            sa,
            cert_serial_hex(&b.cert_der).unwrap(),
            "two certificates must not share a serial"
        );
        assert!(
            sa.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(
            crate::middleware::authz::normalize_serial(&sa).as_deref(),
            Some(sa.as_str()),
            "already canonical"
        );
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
        assert!(
            config.is_ok(),
            "should build a valid ServerConfig from real PEM files: {:?}",
            config.err()
        );
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
