//! Stealth address protocol for the Waecan protocol.
//!
//! Implements one-time output key generation (sender side) and output
//! scanning (recipient side) per spec Section 2.2. Every transaction
//! output goes to an unlinkable one-time public key.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::hash::keccak256_to_scalar;

/// Compute a one-time output key and the transaction public key R.
///
/// **Sender side** (Section 2.2.2):
/// - `R = r * G` (embedded in tx as `tx_public_key`)
/// - `P = H_s(r * V) * G + S` (one-time output key)
///
/// Returns `(P, R)`.
pub fn compute_output_key(
    tx_secret: &Scalar,
    recipient_view_pub: &EdwardsPoint,
    recipient_spend_pub: &EdwardsPoint,
) -> (EdwardsPoint, EdwardsPoint) {
    let tx_public_key = tx_secret * ED25519_BASEPOINT_POINT;
    let shared_secret = tx_secret * recipient_view_pub;
    let hs = keccak256_to_scalar(shared_secret.compress().as_bytes());
    let output_key = hs * ED25519_BASEPOINT_POINT + recipient_spend_pub;
    (output_key, tx_public_key)
}

/// Scan a transaction output to check if it belongs to the recipient.
///
/// **Recipient side** (Section 2.2.3):
/// - Compute `P' = H_s(v * R) * G + S`
/// - If `P' == P`, this output is ours.
///
/// Returns `true` if the output belongs to the recipient.
pub fn scan_output(
    tx_public_key: &EdwardsPoint,
    view_private: &Scalar,
    spend_public: &EdwardsPoint,
    output_key: &EdwardsPoint,
) -> bool {
    let shared_secret = view_private * tx_public_key;
    let hs = keccak256_to_scalar(shared_secret.compress().as_bytes());
    let expected_p = hs * ED25519_BASEPOINT_POINT + spend_public;
    expected_p == *output_key
}

/// Derive the one-time private key for spending a received output.
///
/// `x = H_s(v * R) + s` where `s` is the spend private key.
pub fn derive_output_private_key(
    tx_public_key: &EdwardsPoint,
    view_private: &Scalar,
    spend_private: &Scalar,
) -> Scalar {
    let shared_secret = view_private * tx_public_key;
    let hs = keccak256_to_scalar(shared_secret.compress().as_bytes());
    hs + spend_private
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_keypairs, MasterSeed};
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn random_scalar(rng: &mut ChaCha20Rng) -> Scalar {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[test]
    fn test_stealth_roundtrip() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        let tx_secret = random_scalar(&mut rng);

        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public);

        assert!(scan_output(
            &tx_pub,
            &view.private,
            &spend.public,
            &output_key
        ));
    }

    #[test]
    fn test_wrong_view_key_fails() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let (_, wrong_view) = derive_keypairs(&MasterSeed::from_bytes([99u8; 32])).unwrap();

        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let tx_secret = random_scalar(&mut rng);
        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public);

        assert!(!scan_output(
            &tx_pub,
            &wrong_view.private,
            &spend.public,
            &output_key
        ));
    }

    #[test]
    fn test_unlinkable_outputs() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);

        let (ok1, _) = compute_output_key(&random_scalar(&mut rng), &view.public, &spend.public);
        let (ok2, _) = compute_output_key(&random_scalar(&mut rng), &view.public, &spend.public);
        assert_ne!(ok1, ok2);
    }

    #[test]
    fn test_output_private_key_matches() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let tx_secret = random_scalar(&mut rng);

        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public);

        let output_private = derive_output_private_key(&tx_pub, &view.private, &spend.private);
        assert_eq!(output_private * ED25519_BASEPOINT_POINT, output_key);
    }

    #[test]
    fn test_two_recipients() {
        let (s_a, v_a) = derive_keypairs(&MasterSeed::from_bytes([1u8; 32])).unwrap();
        let (s_b, v_b) = derive_keypairs(&MasterSeed::from_bytes([2u8; 32])).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);

        let (ok_a, rp_a) = compute_output_key(&random_scalar(&mut rng), &v_a.public, &s_a.public);
        let (ok_b, rp_b) = compute_output_key(&random_scalar(&mut rng), &v_b.public, &s_b.public);

        // A finds A's, not B's.
        assert!(scan_output(&rp_a, &v_a.private, &s_a.public, &ok_a));
        assert!(!scan_output(&rp_b, &v_a.private, &s_a.public, &ok_b));
        // B finds B's, not A's.
        assert!(scan_output(&rp_b, &v_b.private, &s_b.public, &ok_b));
        assert!(!scan_output(&rp_a, &v_b.private, &s_b.public, &ok_a));
    }
}
