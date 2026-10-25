use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::Args;
use sentinel_hardware::{HardwareError, YubiKeyUnsealer};
use serde_json::{json, Value};

/// Connection details for talking to a running `sentinel-node` over mTLS.
/// The node only accepts clients whose certificate is signed by its CA, so
/// every admin command needs a client identity.
#[derive(Args, Debug, Clone)]
pub struct NodeArgs {
    /// Base URL of the node, e.g. https://127.0.0.1:8443
    #[arg(long)]
    pub node: String,
    /// Client certificate (PEM) presented to the node.
    #[arg(long)]
    pub cert: PathBuf,
    /// Private key (PEM) for the client certificate.
    #[arg(long)]
    pub key: PathBuf,
    /// CA certificate (PEM) that signed the node's server certificate.
    #[arg(long)]
    pub ca: PathBuf,
}

/// What the node said after a share was submitted.
#[derive(Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    Pending { contributed: u64, threshold: u64 },
    Unsealed,
}

pub struct NodeClient {
    http: reqwest::blocking::Client,
    base: String,
}

impl NodeClient {
    pub fn connect(args: &NodeArgs) -> anyhow::Result<Self> {
        // reqwest's TLS stack and our direct rustls dependency each enable
        // a different crypto provider; rustls 0.23 refuses to guess when
        // both are compiled in, so pick `ring` explicitly (exactly what
        // sentinel-node does at startup). The result is ignored on
        // purpose: `Err` just means a provider was already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut identity_pem = std::fs::read(&args.cert).with_context(|| format!("reading {}", args.cert.display()))?;
        identity_pem.extend_from_slice(&std::fs::read(&args.key).with_context(|| format!("reading {}", args.key.display()))?);
        let identity = reqwest::Identity::from_pem(&identity_pem).context("client cert/key are not a valid PEM identity")?;
        let ca = reqwest::Certificate::from_pem(
            &std::fs::read(&args.ca).with_context(|| format!("reading {}", args.ca.display()))?,
        )
        .context("CA file is not a valid PEM certificate")?;

        let http = reqwest::blocking::Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .use_rustls_tls()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { http, base: args.node.trim_end_matches('/').to_string() })
    }

    /// Submits one key holder's decrypted share (already hex-encoded).
    pub fn submit_share(&self, holder_id: &str, share_hex: &str) -> anyhow::Result<SubmitOutcome> {
        let resp = self
            .http
            .post(format!("{}/sys/unseal", self.base))
            .json(&json!({ "holder_id": holder_id, "share": share_hex }))
            .send()
            .context("could not reach the node")?;
        let status = resp.status();
        let body: Value = resp.json().unwrap_or(Value::Null);
        parse_submit_response(status.as_u16(), &body)
    }

    pub fn seal(&self) -> anyhow::Result<()> {
        let resp = self.http.post(format!("{}/sys/seal", self.base)).send().context("could not reach the node")?;
        if resp.status().is_success() {
            Ok(())
        } else {
            bail!("node refused to seal: HTTP {}", resp.status())
        }
    }

    pub fn reset_session(&self) -> anyhow::Result<()> {
        let resp = self.http.delete(format!("{}/sys/unseal", self.base)).send().context("could not reach the node")?;
        if resp.status().is_success() {
            Ok(())
        } else {
            bail!("node refused to reset the unseal session: HTTP {}", resp.status())
        }
    }
}

/// Pure so it can be unit-tested without a network.
pub fn parse_submit_response(status: u16, body: &Value) -> anyhow::Result<SubmitOutcome> {
    if status != 200 {
        let msg = body["error"].as_str().unwrap_or("no error message");
        bail!("node rejected the share (HTTP {status}): {msg}");
    }
    match body["status"].as_str() {
        Some("unsealed") => Ok(SubmitOutcome::Unsealed),
        Some("pending") => Ok(SubmitOutcome::Pending {
            contributed: body["contributed"].as_u64().unwrap_or(0),
            threshold: body["threshold"].as_u64().unwrap_or(0),
        }),
        other => bail!("unexpected response from node: status = {other:?}"),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Interactive unseal: prompts each key holder in turn to plug in their
/// YubiKey, decrypts *only that holder's share* on the device, and sends it
/// to the node. The node counts the quorum and verifies the reconstructed
/// key; this tool never assembles the key itself.
pub fn run(client: &NodeClient, encrypted_shares: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    let unsealer = YubiKeyUnsealer::new(yubikey::piv::SlotId::KeyManagement);
    println!("Sentinel unseal: {} key holders available.", encrypted_shares.len());

    for (holder_id, encrypted_share) in encrypted_shares {
        println!("\nInsert {holder_id}'s YubiKey and press Enter (or Ctrl+C to abort)...");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;

        let pin = rpassword::prompt_password(format!("PIN for {holder_id}: "))?;

        match unsealer.decrypt_share(pin.as_bytes(), encrypted_share) {
            Ok(decrypted) => match client.submit_share(holder_id, &to_hex(&decrypted)) {
                Ok(SubmitOutcome::Unsealed) => {
                    println!("  [ok] {holder_id} confirmed. Quorum reached: the node is unsealed.");
                    return Ok(());
                }
                Ok(SubmitOutcome::Pending { contributed, threshold }) => {
                    println!("  [ok] {holder_id} confirmed ({contributed}/{threshold} so far)");
                }
                Err(e) => println!("  [x] {holder_id}: {e:#}"),
            },
            Err(HardwareError::NoDeviceFound) => println!("  [x] no YubiKey detected, try again"),
            Err(HardwareError::IncorrectPin) => println!("  [x] incorrect PIN for {holder_id}"),
            Err(e) => println!("  [x] {holder_id}: {e}"),
        }
    }

    bail!("ran out of key holders before the node reported a quorum; run again, or use `reset-unseal` to start clean")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn pending_response_is_parsed() {
        let body = json!({ "status": "pending", "contributed": 1, "threshold": 2 });
        assert_eq!(parse_submit_response(200, &body).unwrap(), SubmitOutcome::Pending { contributed: 1, threshold: 2 });
    }

    #[test]
    fn unsealed_response_is_parsed() {
        assert_eq!(parse_submit_response(200, &json!({ "status": "unsealed" })).unwrap(), SubmitOutcome::Unsealed);
    }

    #[test]
    fn rejections_surface_the_nodes_message() {
        let err = parse_submit_response(400, &json!({ "error": "bad request: nope" })).unwrap_err().to_string();
        assert!(err.contains("400") && err.contains("nope"), "got: {err}");
    }

    #[test]
    fn nonsense_responses_are_an_error_not_a_panic() {
        assert!(parse_submit_response(200, &Value::Null).is_err());
        assert!(parse_submit_response(200, &json!({ "status": 7 })).is_err());
        assert!(parse_submit_response(500, &Value::Null).is_err());
    }
}