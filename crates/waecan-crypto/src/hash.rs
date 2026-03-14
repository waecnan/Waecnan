//! Cryptographic hash utilities for the Waecan protocol.
//!
//! Provides Keccak-256 hashing, scalar derivation, and hash-to-point
//! mapping needed by stealth addresses, ring signatures, and key images.


use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 hash of the input data.
///
/// This is the raw hash function used throughout the protocol for
/// scalar derivation and hash-to-point operations. It is NOT SHA-3;
/// Keccak-256 uses the pre-NIST padding.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Map arbitrary data to an Ed25519 scalar via Keccak-256.
///
/// Computes `Keccak-256(data)` and reduces the result modulo the
/// Ed25519 group order `l`. Used for shared secret derivation in
/// stealth addresses: `H_s(r * V)`.
pub fn keccak256_to_scalar(data: &[u8]) -> Scalar {
    let hash = keccak256(data);
    Scalar::from_bytes_mod_order(hash)
}

/// Map an Ed25519 public key to a curve point via iterated hashing.
///
/// Used to compute `H_p(P)` for key image generation: `I = x * H_p(P)`.
/// The mapping uses iterated Keccak-256 hashing until a valid compressed
/// Edwards Y coordinate is found, then multiplies by the cofactor (8)
/// to ensure the result is in the prime-order subgroup.
pub fn hash_to_point(key: &CompressedEdwardsY) -> EdwardsPoint {
    let mut hash_input = key.as_bytes().to_vec();
    loop {
        let hash = keccak256(&hash_input);
        let compressed = CompressedEdwardsY::from_slice(&hash);
        if let Ok(compressed) = compressed {
            if let Some(point) = compressed.decompress() {
                // Multiply by cofactor 8 to ensure prime-order subgroup.
                // Prevents small-subgroup attacks on key images.
                let point = point.mul_by_cofactor();
                if point != EdwardsPoint::default() {
                    return point;
                }
            }
        }
        // If decompression failed or gave identity, iterate.
        hash_input = hash.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    #[test]
    fn test_keccak256_known_vector() {
        // Empty input produces the standard Keccak-256 empty hash.
        let hash = keccak256(b"");
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_keccak256_deterministic() {
        let hash = keccak256(b"waecan");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, keccak256(b"waecan"));
    }

    #[test]
    fn test_keccak256_to_scalar_deterministic() {
        let s1 = keccak256_to_scalar(b"test-data");
        let s2 = keccak256_to_scalar(b"test-data");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_keccak256_to_scalar_different_inputs() {
        let s1 = keccak256_to_scalar(b"input-a");
        let s2 = keccak256_to_scalar(b"input-b");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_hash_to_point_valid_subgroup() {
        let key = ED25519_BASEPOINT_POINT.compress();
        let point = hash_to_point(&key);
        // After cofactor clearing, mul_by_cofactor should be unchanged
        // (point is already in the prime subgroup, so 8*point != identity
        // unless point is identity, which we test separately).
        let cofactored = point.mul_by_cofactor();
        // cofactor * point == 8 * point; for a prime-subgroup element this is just 8*P.
        // It should NOT be identity (identity only if point was a torsion element).
        assert_ne!(cofactored, EdwardsPoint::default());
    }

    #[test]
    fn test_hash_to_point_deterministic() {
        let key = ED25519_BASEPOINT_POINT.compress();
        assert_eq!(hash_to_point(&key), hash_to_point(&key));
    }

    #[test]
    fn test_hash_to_point_not_identity() {
        let key = ED25519_BASEPOINT_POINT.compress();
        assert_ne!(hash_to_point(&key), EdwardsPoint::default());
    }
}
