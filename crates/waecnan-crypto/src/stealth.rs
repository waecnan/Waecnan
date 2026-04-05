use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::hash::keccak256_to_scalar;

pub fn compute_output_key(
    tx_secret: &Scalar,
    recipient_view_pub: &EdwardsPoint,
    recipient_spend_pub: &EdwardsPoint,
    output_index: usize,
) -> (EdwardsPoint, EdwardsPoint) {
    let tx_public_key = tx_secret * ED25519_BASEPOINT_POINT;
    let shared_secret = tx_secret * recipient_view_pub;
    let mut data = shared_secret.compress().as_bytes().to_vec();
    data.extend_from_slice(&(output_index as u64).to_le_bytes());
    let hs = keccak256_to_scalar(&data);
    let output_key = hs * ED25519_BASEPOINT_POINT + recipient_spend_pub;
    (output_key, tx_public_key)
}

pub fn scan_output(
    tx_public_key: &EdwardsPoint,
    view_private: &Scalar,
    spend_public: &EdwardsPoint,
    output_key: &EdwardsPoint,
    output_index: usize,
) -> bool {
    let shared_secret = view_private * tx_public_key;
    let mut data = shared_secret.compress().as_bytes().to_vec();
    data.extend_from_slice(&(output_index as u64).to_le_bytes());
    let hs = keccak256_to_scalar(&data);
    let expected_p = hs * ED25519_BASEPOINT_POINT + spend_public;
    expected_p == *output_key
}

pub fn derive_output_private_key(
    tx_public_key: &EdwardsPoint,
    view_private: &Scalar,
    spend_private: &Scalar,
    output_index: usize,
) -> Scalar {
    let shared_secret = view_private * tx_public_key;
    let mut data = shared_secret.compress().as_bytes().to_vec();
    data.extend_from_slice(&(output_index as u64).to_le_bytes());
    let hs = keccak256_to_scalar(&data);
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
        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public, 0);
        assert!(scan_output(
            &tx_pub,
            &view.private,
            &spend.public,
            &output_key,
            0
        ));
    }

    #[test]
    fn test_wrong_view_key_fails() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let (_, wrong_view) = derive_keypairs(&MasterSeed::from_bytes([99u8; 32])).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let tx_secret = random_scalar(&mut rng);
        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public, 0);
        assert!(!scan_output(
            &tx_pub,
            &wrong_view.private,
            &spend.public,
            &output_key,
            0
        ));
    }

    #[test]
    fn test_unlinkable_outputs() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (ok1, _) = compute_output_key(&random_scalar(&mut rng), &view.public, &spend.public, 0);
        let (ok2, _) = compute_output_key(&random_scalar(&mut rng), &view.public, &spend.public, 1);
        assert_ne!(ok1, ok2);
    }

    #[test]
    fn test_output_private_key_matches() {
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let tx_secret = random_scalar(&mut rng);
        let (output_key, tx_pub) = compute_output_key(&tx_secret, &view.public, &spend.public, 0);
        let output_private = derive_output_private_key(&tx_pub, &view.private, &spend.private, 0);
        assert_eq!(output_private * ED25519_BASEPOINT_POINT, output_key);
    }

    #[test]
    fn test_two_recipients() {
        let (s_a, v_a) = derive_keypairs(&MasterSeed::from_bytes([1u8; 32])).unwrap();
        let (s_b, v_b) = derive_keypairs(&MasterSeed::from_bytes([2u8; 32])).unwrap();
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (ok_a, rp_a) =
            compute_output_key(&random_scalar(&mut rng), &v_a.public, &s_a.public, 0);
        let (ok_b, rp_b) =
            compute_output_key(&random_scalar(&mut rng), &v_b.public, &s_b.public, 0);
        assert!(scan_output(&rp_a, &v_a.private, &s_a.public, &ok_a, 0));
        assert!(!scan_output(&rp_b, &v_a.private, &s_a.public, &ok_b, 0));
        assert!(scan_output(&rp_b, &v_b.private, &s_b.public, &ok_b, 0));
        assert!(!scan_output(&rp_a, &v_b.private, &s_b.public, &ok_a, 0));
    }
}
