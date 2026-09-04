use sentinel_hardware::{HardwareError, QuorumUnseal, UnsealFragment, YubiKeyUnsealer};

/// Interactive quorum unseal: prompts for each key holder to plug in
/// their YubiKey and touch it in turn, stopping the moment `threshold`
/// distinct holders have contributed. `encrypted_shares` maps each
/// holder id to the Shamir share that was encrypted to their PIV key at
/// provisioning time.
pub fn run(threshold: u8, encrypted_shares: &[(String, Vec<u8>)]) -> anyhow::Result<Vec<u8>> {
    let mut quorum = QuorumUnseal::new(threshold);
    let unsealer = YubiKeyUnsealer::new(yubikey::piv::SlotId::KeyManagement);

    println!("Sentinel unseal: {threshold} of {} key holders required.", encrypted_shares.len());

    for (holder_id, encrypted_share) in encrypted_shares {
        if quorum.is_satisfied() {
            break;
        }
        println!("\nInsert {holder_id}'s YubiKey and press Enter (or Ctrl+C to abort)...");
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;

        let pin = rpassword::prompt_password(format!("PIN for {holder_id}: "))?;

        match unsealer.decrypt_share(pin.as_bytes(), encrypted_share) {
            Ok(decrypted) => {
                let share: sentinel_crypto::shamir::ShamirShare = bincode::deserialize(&decrypted)
                    .map_err(|e| anyhow::anyhow!("corrupt decrypted share from {holder_id}: {e}"))?;
                quorum.contribute(UnsealFragment { holder_id: holder_id.clone(), share })?;
                println!(
                    "  ✓ {holder_id} confirmed ({}/{} so far)",
                    quorum.contributed_so_far(),
                    threshold
                );
            }
            Err(HardwareError::NoDeviceFound) => {
                println!("  ✗ no YubiKey detected — try again");
            }
            Err(HardwareError::IncorrectPin) => {
                println!("  ✗ incorrect PIN for {holder_id}");
            }
            Err(e) => {
                println!("  ✗ {holder_id}: {e}");
            }
        }
    }

    if !quorum.is_satisfied() {
        anyhow::bail!(
            "quorum not reached: {}/{} holders confirmed",
            quorum.contributed_so_far(),
            threshold
        );
    }

    let kek = quorum.try_reconstruct()?;
    println!("\nQuorum reached — vault unsealed.");
    Ok(kek)
}