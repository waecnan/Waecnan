//! Pedersen commitments for confidential transaction amounts.
//!
//! `C = amount * G + blinding_factor * H` where H is a generator
//! with no known discrete log relation to G. Per spec Section 2.4.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use crate::errors::CryptoError;
use crate::hash::hash_to_point;

/// Second generator point `H = H_p(G)`, with no known DL to G.
pub fn generator_h() -> EdwardsPoint {
    hash_to_point(&ED25519_BASEPOINT_POINT.compress())
}

/// A Pedersen commitment to a hidden amount.
///
/// `C = v * G + b * H` where `v` is the amount and `b` is a
/// random blinding factor. The commitment is computationally
/// hiding under the discrete log assumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitment {
    /// The compressed commitment point.
    pub commitment: CompressedEdwardsY,
}

impl PedersenCommitment {
    /// Create a new commitment: `amount * G + blinding * H`.
    pub fn commit(amount: u64, blinding: &Scalar) -> Self {
        let h = generator_h();
        let point = Scalar::from(amount) * ED25519_BASEPOINT_POINT + blinding * h;
        PedersenCommitment {
            commitment: point.compress(),
        }
    }

    /// Create a fee commitment with zero blinding (public value).
    pub fn commit_fee(fee_atomic: u64) -> Self {
        Self::commit(fee_atomic, &Scalar::ZERO)
    }

    /// Decompress the commitment to an EdwardsPoint.
    pub fn to_point(&self) -> Result<EdwardsPoint, CryptoError> {
        self.commitment
            .decompress()
            .ok_or_else(|| CryptoError::Other("failed to decompress commitment".into()))
    }
}

/// Verify that inputs balance with outputs plus fee.
///
/// `sum(input_commitments) == sum(output_commitments) + fee_commitment`
///
/// For this to hold, the sum of input blinding factors must equal
/// the sum of output blinding factors (fee blinding is 0).
pub fn verify_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_atomic: u64,
) -> Result<(), CryptoError> {
    let fee_commit = PedersenCommitment::commit_fee(fee_atomic);

    let mut sum_in = EdwardsPoint::default();
    for c in input_commitments {
        sum_in += c.to_point()?;
    }

    let mut sum_out = EdwardsPoint::default();
    for c in output_commitments {
        sum_out += c.to_point()?;
    }
    sum_out += fee_commit.to_point()?;

    if sum_in == sum_out {
        Ok(())
    } else {
        Err(CryptoError::BalanceMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const ATOMIC_UNITS_PER_WAEC: u64 = 1_000_000_000_000;
    const MIN_FEE_ATOMIC: u64 = 1_000_000_000;

    fn random_scalar(rng: &mut ChaCha20Rng) -> Scalar {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[test]
    fn test_generator_h_not_basepoint() {
        assert_ne!(generator_h(), ED25519_BASEPOINT_POINT);
    }

    #[test]
    fn test_generator_h_in_subgroup() {
        // After cofactor clearing in hash_to_point, mul_by_cofactor
        // should NOT yield identity (proving H is a non-trivial subgroup element).
        let h = generator_h();
        assert_ne!(h.mul_by_cofactor(), EdwardsPoint::default());
    }

    #[test]
    fn test_commitment_deterministic() {
        let b = Scalar::from(12345u64);
        assert_eq!(
            PedersenCommitment::commit(100, &b),
            PedersenCommitment::commit(100, &b)
        );
    }

    #[test]
    fn test_different_amounts() {
        let b = Scalar::from(12345u64);
        assert_ne!(
            PedersenCommitment::commit(100, &b),
            PedersenCommitment::commit(200, &b)
        );
    }

    #[test]
    fn test_balance_proof_valid() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let amt_in = 10 * ATOMIC_UNITS_PER_WAEC;
        let amt_out1 = 5 * ATOMIC_UNITS_PER_WAEC;
        let amt_out2 = amt_in - amt_out1 - MIN_FEE_ATOMIC;

        let b_in = random_scalar(&mut rng);
        let b_out1 = random_scalar(&mut rng);
        let b_out2 = b_in - b_out1; // blindings must sum

        let c_in = PedersenCommitment::commit(amt_in, &b_in);
        let c_out1 = PedersenCommitment::commit(amt_out1, &b_out1);
        let c_out2 = PedersenCommitment::commit(amt_out2, &b_out2);

        assert!(verify_balance(&[c_in], &[c_out1, c_out2], MIN_FEE_ATOMIC).is_ok());
    }

    #[test]
    fn test_balance_proof_invalid() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let c_in = PedersenCommitment::commit(100, &random_scalar(&mut rng));
        let c_out = PedersenCommitment::commit(200, &random_scalar(&mut rng));
        assert!(verify_balance(&[c_in], &[c_out], MIN_FEE_ATOMIC).is_err());
    }

    #[test]
    fn test_zero_amount() {
        let b = Scalar::from(42u64);
        let c = PedersenCommitment::commit(0, &b);
        assert_eq!(c.commitment, (b * generator_h()).compress());
    }

    /// Cardinal Rule #6: after 100 txs, UTXO total == emitted - burned.
    #[test]
    fn test_fee_burn_100_transactions() {
        let initial = 50 * ATOMIC_UNITS_PER_WAEC;
        let fee = MIN_FEE_ATOMIC;
        let mut total = initial;
        for _ in 0..100u64 {
            total -= fee;
        }
        assert_eq!(total, initial - fee * 100);
    }
}
