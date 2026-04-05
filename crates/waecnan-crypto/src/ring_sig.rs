//! MLSAG ring signatures for the Waecan protocol.
//!
//! Implements Multilayered Linkable Spontaneous Anonymous Group signatures
//! per spec Section 2.3. Ring size is exactly 11 (1 real + 10 decoys),
//! enforced at consensus level.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;

use crate::errors::CryptoError;
use crate::hash::{hash_to_point, keccak256_to_scalar};

/// Exact ring size enforced at consensus level in V1.
pub const RING_SIZE: usize = 11;

/// A member of a ring (real or decoy output).
#[derive(Clone, Debug)]
pub struct RingMember {
    /// The one-time public key of a real or decoy output.
    pub output_key: EdwardsPoint,
}

/// A ring of public keys for an MLSAG signature.
///
/// Must contain exactly [`RING_SIZE`] members (1 real + 10 decoys).
#[derive(Clone, Debug)]
pub struct Ring {
    /// Ring members; exactly 11 elements in V1.
    pub members: Vec<RingMember>,
}

/// An MLSAG ring signature proving ownership of one key in the ring.
#[derive(Clone, Debug)]
pub struct RingSignature {
    /// Key image `I = x * H_p(P)`. Used for double-spend detection.
    pub key_image: CompressedEdwardsY,
    /// Initial challenge scalar `c_0`.
    pub c_0: Scalar,
    /// Response scalars, one per ring member.
    pub s: Vec<Scalar>,
}

/// Compute the key image for a given private key and output key.
///
/// `I = x * H_p(P)`. Deterministic: same `(x, P)` always yields the
/// same `I`. Included in every transaction for double-spend prevention.
pub fn compute_key_image(spend_private: &Scalar, output_key: &EdwardsPoint) -> CompressedEdwardsY {
    let hp = hash_to_point(&output_key.compress());
    let image = spend_private * hp;
    image.compress()
}

/// Hash message with two EC points to produce a challenge scalar.
fn ring_challenge(message: &[u8], l: &EdwardsPoint, r: &EdwardsPoint) -> Scalar {
    let mut data = Vec::with_capacity(message.len() + 64);
    data.extend_from_slice(message);
    data.extend_from_slice(l.compress().as_bytes());
    data.extend_from_slice(r.compress().as_bytes());
    keccak256_to_scalar(&data)
}

/// Sign a message with an MLSAG ring signature.
///
/// The signer knows the private key at `real_index` in the ring.
/// All other members are decoys.
///
/// # Errors
/// Returns [`CryptoError::InvalidRingSize`] if the ring does not
/// have exactly 11 members.
pub fn mlsag_sign(
    ring: &Ring,
    real_index: usize,
    spend_private: &Scalar,
    message: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<RingSignature, CryptoError> {
    let n = ring.members.len();
    if n != RING_SIZE {
        return Err(CryptoError::InvalidRingSize(n));
    }

    let real_key = &ring.members[real_index].output_key;
    let hp = hash_to_point(&real_key.compress());
    let key_image_point = spend_private * hp;
    let key_image = key_image_point.compress();

    // Random alpha for the real signer.
    let mut alpha_bytes = [0u8; 64];
    rng.fill_bytes(&mut alpha_bytes);
    let alpha = Scalar::from_bytes_mod_order_wide(&alpha_bytes);

    // Random response scalars for all fake members.
    let mut s = vec![Scalar::ZERO; n];
    for (i, s_member) in s.iter_mut().enumerate() {
        if i != real_index {
            let mut s_bytes = [0u8; 64];
            rng.fill_bytes(&mut s_bytes);
            *s_member = Scalar::from_bytes_mod_order_wide(&s_bytes);
        }
    }

    // L_pi = alpha * G, R_pi = alpha * H_p(P_pi)
    let l_real = alpha * ED25519_BASEPOINT_POINT;
    let r_real = alpha * hp;

    // Walk the ring starting from real_index + 1.
    let mut challenges = vec![Scalar::ZERO; n];
    let next_i = (real_index + 1) % n;
    challenges[next_i] = ring_challenge(message, &l_real, &r_real);

    for offset in 1..n {
        let i = (real_index + offset) % n;
        let next = (i + 1) % n;
        let hp_i = hash_to_point(&ring.members[i].output_key.compress());

        let l_i = s[i] * ED25519_BASEPOINT_POINT + challenges[i] * ring.members[i].output_key;
        let r_i = s[i] * hp_i + challenges[i] * key_image_point;

        challenges[next] = ring_challenge(message, &l_i, &r_i);
    }

    // Close the ring.
    s[real_index] = alpha - challenges[real_index] * spend_private;

    Ok(RingSignature {
        key_image,
        c_0: challenges[0],
        s,
    })
}

/// Verify an MLSAG ring signature.
///
/// Recomputes the challenge chain and checks that the final challenge
/// equals `c_0`.
///
/// # Errors
/// Returns [`CryptoError::InvalidRingSize`] or
/// [`CryptoError::InvalidRingSignature`] on failure.
pub fn mlsag_verify(
    ring: &Ring,
    signature: &RingSignature,
    message: &[u8],
) -> Result<(), CryptoError> {
    let n = ring.members.len();
    if n != RING_SIZE {
        return Err(CryptoError::InvalidRingSize(n));
    }
    if signature.s.len() != n {
        return Err(CryptoError::InvalidRingSignature);
    }

    let key_image_point = signature
        .key_image
        .decompress()
        .ok_or(CryptoError::InvalidRingSignature)?;

    let mut c = signature.c_0;
    for i in 0..n {
        let hp_i = hash_to_point(&ring.members[i].output_key.compress());
        let l_i = signature.s[i] * ED25519_BASEPOINT_POINT + c * ring.members[i].output_key;
        let r_i = signature.s[i] * hp_i + c * key_image_point;
        c = ring_challenge(message, &l_i, &r_i);
    }

    if c == signature.c_0 {
        Ok(())
    } else {
        Err(CryptoError::InvalidRingSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_keypairs, MasterSeed};
    use crate::stealth::compute_output_key;
    use rand::SeedableRng;

    fn make_test_ring(real_key: EdwardsPoint, real_index: usize, rng: &mut ChaCha20Rng) -> Ring {
        let mut members = Vec::with_capacity(RING_SIZE);
        for i in 0..RING_SIZE {
            if i == real_index {
                members.push(RingMember {
                    output_key: real_key,
                });
            } else {
                let mut bytes = [0u8; 64];
                rng.fill_bytes(&mut bytes);
                let s = Scalar::from_bytes_mod_order_wide(&bytes);
                members.push(RingMember {
                    output_key: s * ED25519_BASEPOINT_POINT,
                });
            }
        }
        Ring { members }
    }

    #[test]
    fn test_key_image_deterministic() {
        let (spend, _) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();
        let img1 = compute_key_image(&spend.private, &spend.public);
        let img2 = compute_key_image(&spend.private, &spend.public);
        assert_eq!(img1, img2);
    }

    #[test]
    fn test_different_keys_different_images() {
        let (s_a, _) = derive_keypairs(&MasterSeed::from_bytes([1u8; 32])).unwrap();
        let (s_b, _) = derive_keypairs(&MasterSeed::from_bytes([2u8; 32])).unwrap();
        assert_ne!(
            compute_key_image(&s_a.private, &s_a.public),
            compute_key_image(&s_b.private, &s_b.public)
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let seed = MasterSeed::from_bytes([42u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();

        let mut sec_bytes = [0u8; 64];
        rng.fill_bytes(&mut sec_bytes);
        let tx_secret = Scalar::from_bytes_mod_order_wide(&sec_bytes);
        let (output_key, _) = compute_output_key(&tx_secret, &view.public, &spend.public, 0);

        let shared = tx_secret * view.public;
        let hs = crate::hash::keccak256_to_scalar(shared.compress().as_bytes());
        let output_private = hs + spend.private;

        let real_index = 3;
        let ring = make_test_ring(output_key, real_index, &mut rng);
        let msg = b"test tx hash";

        let sig = mlsag_sign(&ring, real_index, &output_private, msg, &mut rng).unwrap();
        assert!(mlsag_verify(&ring, &sig, msg).is_ok());
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (spend, _) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();
        let ring = make_test_ring(spend.public, 5, &mut rng);

        let mut sig = mlsag_sign(&ring, 5, &spend.private, b"msg", &mut rng).unwrap();
        sig.s[0] += Scalar::ONE;
        assert!(mlsag_verify(&ring, &sig, b"msg").is_err());
    }

    #[test]
    fn test_wrong_message_rejected() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (spend, _) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();
        let ring = make_test_ring(spend.public, 0, &mut rng);

        let sig = mlsag_sign(&ring, 0, &spend.private, b"msg-a", &mut rng).unwrap();
        assert!(mlsag_verify(&ring, &sig, b"msg-b").is_err());
    }

    #[test]
    fn test_wrong_ring_size_rejected() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (spend, _) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();

        let mut members = Vec::new();
        for _ in 0..7 {
            let mut b = [0u8; 64];
            rng.fill_bytes(&mut b);
            members.push(RingMember {
                output_key: Scalar::from_bytes_mod_order_wide(&b) * ED25519_BASEPOINT_POINT,
            });
        }
        members[0] = RingMember {
            output_key: spend.public,
        };
        let ring = Ring { members };

        assert!(matches!(
            mlsag_sign(&ring, 0, &spend.private, b"msg", &mut rng),
            Err(CryptoError::InvalidRingSize(7))
        ));
    }

    #[test]
    fn test_key_image_matches_computed() {
        let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
        let (spend, _) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();
        let ring = make_test_ring(spend.public, 2, &mut rng);

        let sig = mlsag_sign(&ring, 2, &spend.private, b"msg", &mut rng).unwrap();
        assert_eq!(
            sig.key_image,
            compute_key_image(&spend.private, &spend.public)
        );
    }
}
