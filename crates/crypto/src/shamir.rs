use rand::RngCore;

/// A single Shamir share: an x-coordinate and the y-value for every byte
/// of the split secret (so an N-byte secret produces shares whose `y` is
/// also N bytes — each byte is a separate, independent GF(256) polynomial
/// evaluation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShamirShare {
    pub x: u8,
    pub y: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum ShamirError {
    #[error("threshold must be at least 2, got {0}")]
    ThresholdTooLow(u8),
    #[error("total shares ({total}) must be >= threshold ({threshold})")]
    NotEnoughShares { total: u8, threshold: u8 },
    #[error("total shares must be between 1 and 255, got {0}")]
    TooManyShares(u16),
    #[error("need at least 2 shares to reconstruct, got {0}")]
    InsufficientSharesToCombine(usize),
    #[error("shares have mismatched secret lengths")]
    MismatchedShareLengths,
    #[error("duplicate x-coordinate in share set: {0}")]
    DuplicateShare(u8),
}

// GF(2^8) multiplication using the AES/Rijndael reduction polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11B), via peasant multiplication with
// reduction on overflow. This is the standard finite field used by
// Shamir's Secret Sharing implementations (e.g. Schneier's `ssss`).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    product
}

// a^254 = a^-1 in GF(256), since the multiplicative group has order 255.
// Computed via repeated squaring so it's O(log n) multiplications rather
// than a 255-step loop.
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "zero has no multiplicative inverse in GF(256)");
    let a2 = gf_mul(a, a);
    let a4 = gf_mul(a2, a2);
    let a8 = gf_mul(a4, a4);
    let a16 = gf_mul(a8, a8);
    let a32 = gf_mul(a16, a16);
    let a64 = gf_mul(a32, a32);
    let a128 = gf_mul(a64, a64);
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2 = 0b11111110
    let mut r = a128;
    r = gf_mul(r, a64);
    r = gf_mul(r, a32);
    r = gf_mul(r, a16);
    r = gf_mul(r, a8);
    r = gf_mul(r, a4);
    r = gf_mul(r, a2);
    r
}

fn split_byte(secret_byte: u8, threshold: u8, total_shares: u8, rng: &mut impl RngCore) -> Vec<(u8, u8)> {
    // Random polynomial of degree (threshold - 1) whose constant term is
    // the secret byte: p(x) = secret + c1*x + c2*x^2 + ... + c_{t-1}*x^{t-1}.
    let mut coeffs = Vec::with_capacity(threshold as usize);
    coeffs.push(secret_byte);
    let mut rand_byte = [0u8; 1];
    for _ in 1..threshold {
        rng.fill_bytes(&mut rand_byte);
        coeffs.push(rand_byte[0]);
    }

    (1..=total_shares)
        .map(|x| {
            let mut y = 0u8;
            let mut x_pow = 1u8; // x^0
            for &c in &coeffs {
                y ^= gf_mul(c, x_pow);
                x_pow = gf_mul(x_pow, x);
            }
            (x, y)
        })
        .collect()
}

fn combine_byte(points: &[(u8, u8)]) -> u8 {
    // Lagrange interpolation evaluated at x = 0: secret = sum_i y_i * L_i(0),
    // where in GF(2) arithmetic "0 - x_j" is just "x_j" and subtraction is
    // XOR, so L_i(0) = product_{j != i} x_j / (x_i XOR x_j).
    let mut secret = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                numerator = gf_mul(numerator, xj);
                denominator = gf_mul(denominator, xi ^ xj);
            }
        }
        let lagrange_coeff = gf_mul(numerator, gf_inv(denominator));
        secret ^= gf_mul(yi, lagrange_coeff);
    }
    secret
}

/// Splits `secret` into `total_shares` shares such that any `threshold`
/// of them reconstruct it exactly, and any fewer reveal nothing about it
/// (information-theoretic security, not just computational — this is
/// Shamir's classic guarantee). Each byte of the secret is split with an
/// independent random polynomial.
pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    total_shares: u8,
    rng: &mut impl RngCore,
) -> Result<Vec<ShamirShare>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooLow(threshold));
    }
    if total_shares < threshold {
        return Err(ShamirError::NotEnoughShares { total: total_shares, threshold });
    }
    if total_shares == 0 {
        return Err(ShamirError::TooManyShares(0));
    }

    // x-coordinates run 1..=total_shares (0 is reserved: that's the point
    // that encodes the secret itself, and must never be handed out).
    let mut per_share_bytes: Vec<Vec<u8>> = (0..total_shares).map(|_| Vec::with_capacity(secret.len())).collect();
    for &byte in secret {
        let points = split_byte(byte, threshold, total_shares, rng);
        for (idx, (_x, y)) in points.into_iter().enumerate() {
            per_share_bytes[idx].push(y);
        }
    }

    Ok((1..=total_shares)
        .zip(per_share_bytes)
        .map(|(x, y)| ShamirShare { x, y })
        .collect())
}

/// Reconstructs the original secret from `shares`. Any `threshold` (or
/// more) correct shares reproduce the exact secret; fewer than that, or
/// the wrong shares, silently produce garbage — Shamir provides no
/// integrity check on its own, which is why Sentinel always verifies the
/// reconstructed KEK against the audit-log HMAC before trusting an
/// unseal (Phase 4).
pub fn combine_shares(shares: &[ShamirShare]) -> Result<Vec<u8>, ShamirError> {
    if shares.len() < 2 {
        return Err(ShamirError::InsufficientSharesToCombine(shares.len()));
    }
    let secret_len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != secret_len) {
        return Err(ShamirError::MismatchedShareLengths);
    }
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.x) {
            return Err(ShamirError::DuplicateShare(s.x));
        }
    }

    let mut secret = vec![0u8; secret_len];
    for byte_idx in 0..secret_len {
        let points: Vec<(u8, u8)> = shares.iter().map(|s| (s.x, s.y[byte_idx])).collect();
        secret[byte_idx] = combine_byte(&points);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trips_with_exact_threshold() {
        let secret = b"32-byte-kek-material-goes-here!";
        let shares = split_secret(secret, 2, 3, &mut OsRng).unwrap();
        let recovered = combine_shares(&shares[..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn round_trips_with_more_than_threshold() {
        let secret = b"another-secret";
        let shares = split_secret(secret, 3, 5, &mut OsRng).unwrap();
        let recovered = combine_shares(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn any_threshold_subset_works() {
        let secret = b"quorum-independent-of-which-subset";
        let shares = split_secret(secret, 3, 5, &mut OsRng).unwrap();
        let subset_a = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let subset_b = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        assert_eq!(combine_shares(&subset_a).unwrap(), secret);
        assert_eq!(combine_shares(&subset_b).unwrap(), secret);
    }

    #[test]
    fn below_threshold_does_not_reconstruct_correctly() {
        let secret = b"12345678901234567890123456789012";
        let shares = split_secret(secret, 3, 5, &mut OsRng).unwrap();
        // Only 2 of the required 3 shares — Shamir gives no integrity
        // signal here, it just silently produces the wrong bytes.
        let recovered = combine_shares(&shares[..2]).unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn rejects_threshold_below_two() {
        assert!(matches!(
            split_secret(b"x", 1, 3, &mut OsRng),
            Err(ShamirError::ThresholdTooLow(1))
        ));
    }

    #[test]
    fn rejects_total_less_than_threshold() {
        assert!(matches!(
            split_secret(b"x", 3, 2, &mut OsRng),
            Err(ShamirError::NotEnoughShares { total: 2, threshold: 3 })
        ));
    }

    #[test]
    fn rejects_mismatched_share_lengths() {
        let mut shares = split_secret(b"abcd", 2, 3, &mut OsRng).unwrap();
        shares[0].y.pop();
        assert!(matches!(combine_shares(&shares[..2]), Err(ShamirError::MismatchedShareLengths)));
    }

    #[test]
    fn rejects_duplicate_shares() {
        let shares = split_secret(b"abcd", 2, 3, &mut OsRng).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(matches!(combine_shares(&dup), Err(ShamirError::DuplicateShare(_))));
    }

    #[test]
    fn gf_inv_is_correct_multiplicative_inverse() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "failed for a={a}");
        }
    }

    #[test]
    fn empty_secret_round_trips() {
        let shares = split_secret(b"", 2, 3, &mut OsRng).unwrap();
        let recovered = combine_shares(&shares[..2]).unwrap();
        assert_eq!(recovered, b"");
    }
}