//! Vault provisioning: generate the root key, split it into shares, protect
//! each share for its holder, and produce the canary every node verifies a
//! reconstructed key against.
//!
//! The root key exists in this process only while `provision` runs. It is never
//! written to disk; what lands on disk is the canary (not secret), and one
//! share file per holder. Any `threshold` shares rebuild the key; fewer reveal
//! nothing about it.
//!
//! Share protection:
//! * `passphrase` (default): the share is encrypted under a key derived from
//!   the holder's passphrase with Argon2id, using AES-256-GCM. The holder's
//!   name is authenticated inside the ciphertext, so files cannot be swapped.
//! * `plain`: the share as hex. For development and automation only.
//!
//! Hardware (YubiKey) protection is deliberately not offered here: that code
//! path has never been run against a device (see `sentinel-hardware`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use rand::rngs::OsRng;
use rand::RngCore;
use sentinel_crypto::envelope::{self, EnvelopeCiphertext, KEY_LEN};
use sentinel_crypto::shamir::{self, ShamirShare};
use sentinel_crypto::{canary, kdf, SecretBytes};
use serde::{Deserialize, Serialize};

pub const MIN_PASSPHRASE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFormat {
    Passphrase,
    Plain,
}

pub struct InitParams {
    pub holders: Vec<String>,
    pub threshold: u8,
    pub out: PathBuf,
    pub format: ShareFormat,
}

#[derive(Debug)]
pub struct InitReport {
    pub canary_file: PathBuf,
    pub share_files: Vec<(String, PathBuf)>,
    pub instructions: PathBuf,
}

// ---------------------------------------------------------------------------
// Passphrase-protected share files
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ShareFile {
    version: u8,
    kdf: String,
    salt: String,
    envelope: EnvelopeCiphertext,
}

#[derive(Serialize, Deserialize)]
struct SharePayload {
    holder: String,
    share: Vec<u8>,
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn passphrase_key(passphrase: &str, salt: &[u8]) -> anyhow::Result<SecretBytes> {
    kdf::derive_kek_argon2(passphrase.as_bytes(), salt).map_err(|_| anyhow::anyhow!("key derivation failed"))
}

/// Encrypts a holder's bincode-encoded share under their passphrase.
pub fn seal_share(holder: &str, share_bytes: &[u8], passphrase: &str) -> anyhow::Result<String> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        bail!("passphrase for {holder} is too short: use at least {MIN_PASSPHRASE_LEN} characters");
    }
    let salt = kdf::random_salt();
    let key = passphrase_key(passphrase, &salt)?;
    let payload = bincode::serialize(&SharePayload { holder: holder.to_string(), share: share_bytes.to_vec() })?;
    let envelope = envelope::encrypt(&key, &payload).map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let file = ShareFile { version: 1, kdf: "argon2id".into(), salt: to_hex(&salt), envelope };
    Ok(serde_json::to_string_pretty(&file)?)
}

/// Decrypts a share file. Returns the holder it was made for and the
/// bincode-encoded share. A wrong passphrase and a damaged file are
/// deliberately indistinguishable.
pub fn open_share(file_json: &str, passphrase: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let file: ShareFile = serde_json::from_str(file_json).context("this is not a Sentinel share file")?;
    if file.version != 1 || file.kdf != "argon2id" {
        bail!("unsupported share file (version {}, kdf {})", file.version, file.kdf);
    }
    let salt = from_hex(&file.salt).filter(|s| s.len() == kdf::SALT_LEN).context("the share file's salt is damaged")?;
    let key = passphrase_key(passphrase, &salt)?;
    let plain = envelope::decrypt(&key, &file.envelope).map_err(|_| anyhow::anyhow!("wrong passphrase, or the share file is damaged"))?;
    let payload: SharePayload = bincode::deserialize(&plain).map_err(|_| anyhow::anyhow!("wrong passphrase, or the share file is damaged"))?;
    Ok((payload.holder, payload.share))
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

fn valid_holder(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Creates a new vault's key material under `params.out`.
///
/// `passphrases` maps holder name to passphrase and is required (for every
/// holder) when the format is `Passphrase`.
pub fn provision(params: &InitParams, passphrases: &HashMap<String, String>) -> anyhow::Result<InitReport> {
    let n = params.holders.len();
    if params.threshold < 2 {
        bail!("the threshold must be at least 2: a threshold of 1 means any single share is the whole key");
    }
    if n < params.threshold as usize {
        bail!("{n} holders cannot satisfy a threshold of {}", params.threshold);
    }
    if n > 255 {
        bail!("at most 255 holders are supported");
    }
    let unique: HashSet<&String> = params.holders.iter().collect();
    if unique.len() != n {
        bail!("holder names must be unique");
    }
    if let Some(bad) = params.holders.iter().find(|h| !valid_holder(h)) {
        bail!("invalid holder name {bad:?}: use 1-64 letters, digits, '-', '_' or '.'");
    }
    if params.format == ShareFormat::Passphrase {
        for h in &params.holders {
            let p = passphrases.get(h).with_context(|| format!("no passphrase supplied for {h}"))?;
            if p.chars().count() < MIN_PASSPHRASE_LEN {
                bail!("passphrase for {h} is too short: use at least {MIN_PASSPHRASE_LEN} characters");
            }
        }
    }
    if params.out.exists() && std::fs::read_dir(&params.out)?.next().is_some() {
        bail!("{} already exists and is not empty; refusing to overwrite key material", params.out.display());
    }
    std::fs::create_dir_all(&params.out)?;

    // Do everything in a way that leaves nothing half-written on failure.
    match write_all(params, passphrases) {
        Ok(report) => Ok(report),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&params.out);
            Err(e)
        }
    }
}

fn write_all(params: &InitParams, passphrases: &HashMap<String, String>) -> anyhow::Result<InitReport> {
    let mut key_bytes = vec![0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key_bytes);
    let kek = SecretBytes::new(key_bytes);

    let shares = shamir::split_secret(kek.expose(), params.threshold, params.holders.len() as u8, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("splitting the key failed: {e}"))?;

    let canary_blob = bincode::serialize(&canary::create(&kek).map_err(|_| anyhow::anyhow!("creating the canary failed"))?)?;
    let canary_file = params.out.join("canary.bin");
    std::fs::write(&canary_file, &canary_blob)?;

    let mut share_files = Vec::new();
    let mut written_shares: Vec<(String, Vec<u8>)> = Vec::new(); // what a holder will later submit
    for (holder, share) in params.holders.iter().zip(shares.iter()) {
        let share_bytes = bincode::serialize(share)?;
        let (name, content): (String, Vec<u8>) = match params.format {
            ShareFormat::Plain => (format!("share-{holder}.hex"), to_hex(&share_bytes).into_bytes()),
            ShareFormat::Passphrase => (format!("share-{holder}.enc"), seal_share(holder, &share_bytes, &passphrases[holder])?.into_bytes()),
        };
        let path = params.out.join(name);
        write_private(&path, &content)?;
        share_files.push((holder.clone(), path));
        written_shares.push((holder.clone(), share_bytes));
    }

    // Self-test: rebuild the key from what was just written to disk, using the
    // same code a holder will use later, and check it opens the canary. If this
    // fails the vault would be unrecoverable, so nothing is handed over.
    let mut recovered: Vec<ShamirShare> = Vec::new();
    for (holder, path) in share_files.iter().take(params.threshold as usize) {
        let raw = std::fs::read_to_string(path)?;
        let share_bytes = match params.format {
            ShareFormat::Plain => from_hex(raw.trim()).context("self-test: share file is not hex")?,
            ShareFormat::Passphrase => {
                let (who, bytes) = open_share(&raw, &passphrases[holder])?;
                if &who != holder {
                    bail!("self-test: share file for {holder} names {who}");
                }
                bytes
            }
        };
        recovered.push(bincode::deserialize(&share_bytes)?);
    }
    let rebuilt = shamir::combine_shares(&recovered).map_err(|e| anyhow::anyhow!("self-test: recombining failed: {e}"))?;
    let canary_parsed: EnvelopeCiphertext = bincode::deserialize(&canary_blob)?;
    if !canary::verify(&SecretBytes::new(rebuilt), &canary_parsed) {
        bail!("self-test failed: the shares written to disk do not rebuild the key. Nothing was kept");
    }
    drop(written_shares);

    let instructions = params.out.join("PROVISIONING.txt");
    let holders = params.holders.join(", ");
    let (format_name, passphrase_note, unseal_cmd) = match params.format {
        ShareFormat::Passphrase => (
            "passphrase-protected (Argon2id + AES-256-GCM)",
            "   Each holder chose a passphrase; it is not recorded anywhere. A lost\n   passphrase means that share is lost.\n",
            "sentinel-cli unseal-file --node https://HOST:PORT --cert C --key K --ca CA --file share-<name>.enc",
        ),
        ShareFormat::Plain => (
            "PLAIN HEX - development only; anyone holding a file holds that share outright",
            "   WARNING: these files are unprotected. Encrypt them yourself before sending.\n",
            "sentinel-cli submit-share --node https://HOST:PORT --cert C --key K --ca CA --holder <name> < share-<name>.hex",
        ),
    };
    // A raw string, so the indentation below is exactly what lands in the file
    // (a `\` line continuation in a normal string would swallow it).
    let template = r#"Sentinel vault provisioning
===========================

Holders (@COUNT@): @HOLDERS@
Threshold: @THRESHOLD@ of @COUNT@ holders must submit their share to unseal a node.
Share format: @FORMAT@

1. Give each holder ONLY their own share-<name> file, over a channel you trust.
@NOTE@
2. Copy canary.bin to every node (it is not secret) and set in its config:
     canary_file      = "/path/to/canary.bin"
     unseal_threshold = @THRESHOLD@
   The canary is installed into the node's storage at startup. With it in
   place the node never has to trust the first unseal.

3. To unseal, each holder runs (separately, from anywhere that can reach the node):
     @UNSEAL_CMD@

4. Delete this directory's share files from this machine once distributed.

The root key was never written to disk.
"#;
    let text = template
        .replace("@COUNT@", &params.holders.len().to_string())
        .replace("@HOLDERS@", &holders)
        .replace("@THRESHOLD@", &params.threshold.to_string())
        .replace("@FORMAT@", format_name)
        .replace("@NOTE@", passphrase_note)
        .replace("@UNSEAL_CMD@", unseal_cmd);
    std::fs::write(&instructions, text)?;

    Ok(InitReport { canary_file, share_files, instructions })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(holders: &[&str]) -> HashMap<String, String> {
        holders.iter().map(|h| (h.to_string(), format!("correct horse battery {h}"))).collect()
    }

    fn params(dir: &Path, holders: &[&str], threshold: u8, format: ShareFormat) -> InitParams {
        InitParams { holders: holders.iter().map(|s| s.to_string()).collect(), threshold, out: dir.join("vault"), format }
    }

    #[test]
    fn a_passphrase_share_round_trips_and_binds_the_holder() {
        let json = seal_share("alice", b"share-bytes", "a long passphrase!").unwrap();
        let (who, bytes) = open_share(&json, "a long passphrase!").unwrap();
        assert_eq!((who.as_str(), bytes.as_slice()), ("alice", &b"share-bytes"[..]));
        assert!(!json.contains("share-bytes"), "the share must not appear in the clear");
    }

    #[test]
    fn a_wrong_passphrase_or_damaged_file_fails_with_one_indistinguishable_error() {
        let json = seal_share("alice", b"x", "a long passphrase!").unwrap();
        let wrong = open_share(&json, "another passphrase!").unwrap_err().to_string();
        assert!(wrong.contains("wrong passphrase"));

        let mut file: serde_json::Value = serde_json::from_str(&json).unwrap();
        file["envelope"]["ciphertext"][0] = serde_json::json!(255 - file["envelope"]["ciphertext"][0].as_u64().unwrap());
        let damaged = open_share(&file.to_string(), "a long passphrase!").unwrap_err().to_string();
        assert_eq!(wrong, damaged, "an attacker must learn nothing from which error they get");

        assert!(open_share("not json", "x").is_err());
    }

    #[test]
    fn short_passphrases_are_refused() {
        assert!(seal_share("alice", b"x", "short").is_err());
    }

    #[test]
    fn two_seals_of_the_same_share_differ() {
        let a = seal_share("alice", b"x", "a long passphrase!").unwrap();
        let b = seal_share("alice", b"x", "a long passphrase!").unwrap();
        assert_ne!(a, b, "fresh salt and nonces every time");
    }

    #[test]
    fn provisioning_produces_a_canary_and_one_protected_share_per_holder() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), &["alice", "bob", "carol"], 2, ShareFormat::Passphrase);
        let report = provision(&p, &pass(&["alice", "bob", "carol"])).unwrap();

        assert!(report.canary_file.exists() && report.instructions.exists());
        assert_eq!(report.share_files.len(), 3);
        let listing: Vec<String> = std::fs::read_dir(&p.out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(listing.iter().all(|f| f == "canary.bin" || f == "PROVISIONING.txt" || f.starts_with("share-")), "{listing:?}");
    }

    #[test]
    fn any_threshold_of_holders_rebuilds_a_key_that_opens_the_canary_and_fewer_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), &["alice", "bob", "carol"], 2, ShareFormat::Passphrase);
        let phrases = pass(&["alice", "bob", "carol"]);
        let report = provision(&p, &phrases).unwrap();
        let canary_blob: EnvelopeCiphertext = bincode::deserialize(&std::fs::read(&report.canary_file).unwrap()).unwrap();

        let load = |holder: &str| -> ShamirShare {
            let path = &report.share_files.iter().find(|(h, _)| h == holder).unwrap().1;
            let (_, bytes) = open_share(&std::fs::read_to_string(path).unwrap(), &phrases[holder]).unwrap();
            bincode::deserialize(&bytes).unwrap()
        };
        for pair in [["alice", "bob"], ["bob", "carol"], ["alice", "carol"]] {
            let key = shamir::combine_shares(&[load(pair[0]), load(pair[1])]).unwrap();
            assert!(canary::verify(&SecretBytes::new(key), &canary_blob), "{pair:?}");
        }
        let one = shamir::combine_shares(&[load("alice")]);
        assert!(one.map(|k| !canary::verify(&SecretBytes::new(k), &canary_blob)).unwrap_or(true), "a single share must not open the canary");
    }

    #[test]
    fn plain_format_writes_hex_that_the_node_endpoint_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), &["a", "b", "c"], 2, ShareFormat::Plain);
        let report = provision(&p, &HashMap::new()).unwrap();
        let hex = std::fs::read_to_string(&report.share_files[0].1).unwrap();
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()) && !hex.is_empty());
        let share: ShamirShare = bincode::deserialize(&from_hex(&hex).unwrap()).unwrap();
        assert!(share.x >= 1 && share.y.len() == KEY_LEN);
        assert!(std::fs::read_to_string(&report.instructions).unwrap().contains("PLAIN HEX"), "the file must say it is unprotected");
    }

    #[test]
    fn the_instructions_file_keeps_its_indentation_and_fills_in_every_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), &["alice", "bob", "carol"], 2, ShareFormat::Passphrase);
        let report = provision(&p, &pass(&["alice", "bob", "carol"])).unwrap();
        let text = std::fs::read_to_string(&report.instructions).unwrap();

        assert!(!text.contains('@'), "an unfilled placeholder is left in:\n{text}");
        assert!(text.contains("Holders (3): alice, bob, carol"), "{text}");
        assert!(text.contains("Threshold: 2 of 3 holders"), "{text}");
        assert!(text.contains("\n     canary_file      = \"/path/to/canary.bin\"\n"), "config lines must stay indented:\n{text}");
        assert!(text.contains("\n     unseal_threshold = 2\n"), "{text}");
        assert!(text.contains("\n     sentinel-cli unseal-file "), "the command must stay indented:\n{text}");
        assert!(text.contains("A lost\n   passphrase means that share is lost."), "{text}");
    }

    #[test]
    fn bad_parameters_are_refused_and_leave_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let phrases = pass(&["alice", "bob", "carol"]);
        let cases: Vec<(Vec<&str>, u8)> = vec![
            (vec!["alice", "bob"], 1),            // threshold below 2
            (vec!["alice", "bob"], 3),            // threshold above holders
            (vec!["alice", "alice", "bob"], 2),   // duplicate holder
            (vec!["al ice", "bob"], 2),           // invalid name
            (vec!["../evil", "bob"], 2),          // path-ish name
        ];
        for (holders, threshold) in cases {
            let p = params(dir.path(), &holders, threshold, ShareFormat::Passphrase);
            assert!(provision(&p, &phrases).is_err(), "{holders:?}/{threshold}");
            assert!(!p.out.exists(), "a refused run must not create the output directory");
        }
        let mut short = pass(&["alice", "bob"]);
        short.insert("bob".into(), "short".into());
        assert!(provision(&params(dir.path(), &["alice", "bob"], 2, ShareFormat::Passphrase), &short).is_err());
        let mut missing = pass(&["alice"]);
        missing.remove("alice");
        assert!(provision(&params(dir.path(), &["alice", "bob"], 2, ShareFormat::Passphrase), &missing).is_err());
    }

    #[test]
    fn it_never_overwrites_existing_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), &["alice", "bob"], 2, ShareFormat::Plain);
        provision(&p, &HashMap::new()).unwrap();
        let before = std::fs::read(p.out.join("canary.bin")).unwrap();
        assert!(provision(&p, &HashMap::new()).is_err(), "a second run into the same directory must be refused");
        assert_eq!(std::fs::read(p.out.join("canary.bin")).unwrap(), before);
    }

    #[test]
    fn two_vaults_never_share_a_canary() {
        let dir = tempfile::tempdir().unwrap();
        let mut p1 = params(dir.path(), &["a", "b"], 2, ShareFormat::Plain);
        let mut p2 = params(dir.path(), &["a", "b"], 2, ShareFormat::Plain);
        p1.out = dir.path().join("one");
        p2.out = dir.path().join("two");
        let r1 = provision(&p1, &HashMap::new()).unwrap();
        let r2 = provision(&p2, &HashMap::new()).unwrap();
        assert_ne!(std::fs::read(r1.canary_file).unwrap(), std::fs::read(r2.canary_file).unwrap());
    }
}