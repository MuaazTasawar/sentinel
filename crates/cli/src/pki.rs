//! Minimal PKI tooling: create a certificate authority and issue node and
//! client certificates from it, so a deployment does not depend on hand-run
//! `openssl` incantations.
//!
//! Keys are ECDSA P-256. A `node` certificate carries both serverAuth and
//! clientAuth (a node is a server to clients and a client to its peers); a
//! `client` certificate carries clientAuth only. The certificate's Common Name
//! is the identity the node's authorization policy matches on.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    Node,
    Client,
}

fn validate_cn(cn: &str) -> anyhow::Result<()> {
    if cn.is_empty() || cn.len() > 64 || !cn.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ')) {
        bail!("invalid common name {cn:?}: use 1-64 letters, digits, space, '-', '_' or '.'");
    }
    Ok(())
}

fn file_stem(cn: &str) -> String {
    cn.replace(' ', "-")
}

fn validity(params: &mut CertificateParams, days: u32) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(days as i64);
}

fn write_new(path: &Path, contents: &str, private: bool) -> anyhow::Result<()> {
    if path.exists() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

/// Creates `ca.crt` and `ca.key` in `out`.
pub fn create_ca(out: &Path, cn: &str, days: u32) -> anyhow::Result<(PathBuf, PathBuf)> {
    validate_cn(cn)?;
    std::fs::create_dir_all(out)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut params, days);
    let cert = params.self_signed(&key)?;

    let (crt, k) = (out.join("ca.crt"), out.join("ca.key"));
    write_new(&crt, &cert.pem(), false)?;
    write_new(&k, &key.serialize_pem(), true)?;
    Ok((crt, k))
}

/// Issues `<cn>.crt` and `<cn>.key` in `out`, signed by the CA in `ca_dir`.
/// `sans` may mix DNS names and IP addresses (needed for node certificates,
/// which clients connect to by name or address).
pub fn issue(ca_dir: &Path, out: &Path, cn: &str, kind: CertKind, sans: &[String], days: u32) -> anyhow::Result<(PathBuf, PathBuf)> {
    validate_cn(cn)?;
    if kind == CertKind::Node && sans.is_empty() {
        bail!("a node certificate needs at least one --san (DNS name or IP address) so clients can verify it");
    }
    let ca_pem = std::fs::read_to_string(ca_dir.join("ca.crt")).with_context(|| format!("reading {}/ca.crt", ca_dir.display()))?;
    let ca_key_pem = std::fs::read_to_string(ca_dir.join("ca.key")).with_context(|| format!("reading {}/ca.key", ca_dir.display()))?;
    let ca_key = KeyPair::from_pem(&ca_key_pem).context("ca.key is not a valid private key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem).context("ca.crt is not a valid CA certificate")?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = match kind {
        CertKind::Node => vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth],
        CertKind::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
    };
    for san in sans {
        match san.parse::<IpAddr>() {
            Ok(ip) => params.subject_alt_names.push(SanType::IpAddress(ip)),
            Err(_) => params.subject_alt_names.push(SanType::DnsName(san.clone().try_into().with_context(|| format!("invalid DNS name {san:?}"))?)),
        }
    }
    validity(&mut params, days);

    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca_cert, &ca_key)?;

    std::fs::create_dir_all(out)?;
    let stem = file_stem(cn);
    let (crt, k) = (out.join(format!("{stem}.crt")), out.join(format!("{stem}.key")));
    write_new(&crt, &cert.pem(), false)?;
    write_new(&k, &key.serialize_pem(), true)?;
    Ok((crt, k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    fn parse(pem_text: &str) -> Vec<u8> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes()).unwrap();
        pem.contents
    }

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        create_ca(&ca, "Sentinel Test CA", 30).unwrap();
        (dir, ca)
    }

    #[test]
    fn the_ca_is_a_ca_and_self_signed() {
        let (_d, ca) = setup();
        let der = parse(&std::fs::read_to_string(ca.join("ca.crt")).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert!(cert.is_ca());
        assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "Sentinel Test CA");
        assert!(cert.verify_signature(None).is_ok(), "self-signed");
    }

    #[test]
    fn a_node_certificate_chains_to_the_ca_with_the_right_identity_and_usages() {
        let (d, ca) = setup();
        let out = d.path().join("pki");
        let (crt, _) = issue(&ca, &out, "node1", CertKind::Node, &["localhost".into(), "127.0.0.1".into()], 30).unwrap();

        let ca_der = parse(&std::fs::read_to_string(ca.join("ca.crt")).unwrap());
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
        let der = parse(&std::fs::read_to_string(crt).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "node1");
        assert_eq!(cert.issuer().iter_common_name().next().unwrap().as_str().unwrap(), "Sentinel Test CA");
        assert!(!cert.is_ca(), "a leaf must not be able to issue certificates");
        assert!(cert.verify_signature(Some(ca_cert.public_key())).is_ok(), "signed by the CA");

        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && eku.client_auth);
        let names = &cert.subject_alternative_name().unwrap().unwrap().value.general_names;
        assert!(names.iter().any(|n| matches!(n, GeneralName::DNSName("localhost"))), "{names:?}");
        assert!(names.iter().any(|n| matches!(n, GeneralName::IPAddress(ip) if *ip == [127u8, 0, 0, 1])), "{names:?}");
    }

    #[test]
    fn a_client_certificate_is_client_auth_only() {
        let (d, ca) = setup();
        let (crt, _) = issue(&ca, &d.path().join("pki"), "app-writer", CertKind::Client, &[], 30).unwrap();
        let der = parse(&std::fs::read_to_string(crt).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
    }

    #[test]
    fn a_certificate_does_not_verify_against_a_different_ca() {
        let (d, ca) = setup();
        let other = d.path().join("other-ca");
        create_ca(&other, "Someone Else", 30).unwrap();
        let (crt, _) = issue(&ca, &d.path().join("pki"), "node1", CertKind::Node, &["localhost".into()], 30).unwrap();

        let other_der = parse(&std::fs::read_to_string(other.join("ca.crt")).unwrap());
        let (_, other_cert) = X509Certificate::from_der(&other_der).unwrap();
        let der = parse(&std::fs::read_to_string(crt).unwrap());
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert!(cert.verify_signature(Some(other_cert.public_key())).is_err());
    }

    #[test]
    fn serial_numbers_are_unique_per_certificate() {
        let (d, ca) = setup();
        let serial = |cn: &str| {
            let (crt, _) = issue(&ca, &d.path().join("pki"), cn, CertKind::Client, &[], 30).unwrap();
            let der = parse(&std::fs::read_to_string(crt).unwrap());
            X509Certificate::from_der(&der).unwrap().1.tbs_certificate.serial.to_string()
        };
        assert_ne!(serial("a"), serial("b"));
    }

    #[test]
    fn bad_input_and_overwrites_are_refused() {
        let (d, ca) = setup();
        let out = d.path().join("pki");
        assert!(issue(&ca, &out, "node1", CertKind::Node, &[], 30).is_err(), "a node needs a SAN");
        assert!(issue(&ca, &out, "bad/name", CertKind::Client, &[], 30).is_err());
        assert!(issue(&ca, &out, "", CertKind::Client, &[], 30).is_err());
        assert!(issue(&d.path().join("no-such-ca"), &out, "x", CertKind::Client, &[], 30).is_err());

        issue(&ca, &out, "app", CertKind::Client, &[], 30).unwrap();
        assert!(issue(&ca, &out, "app", CertKind::Client, &[], 30).is_err(), "must not overwrite an existing key");
        assert!(create_ca(&ca, "again", 30).is_err(), "must not overwrite an existing CA");
    }
}