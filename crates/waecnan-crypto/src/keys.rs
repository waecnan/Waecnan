//! Key derivation for the Waecan protocol.
//!
//! Implements master seed generation and HMAC-SHA512 derivation of
//! spend/view keypairs per spec Section 2.1.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha512;

use crate::errors::CryptoError;

type HmacSha512 = Hmac<Sha512>;

/// A 256-bit master seed from which all wallet keys are derived.
///
/// Generated from a CSPRNG (ChaCha20Rng). The seed would be encoded
/// as a 24-word BIP-39 mnemonic for human backup in production.
#[derive(Clone)]
pub struct MasterSeed(pub(crate) [u8; 32]);

impl MasterSeed {
    /// Generate a new random master seed from system entropy.
    ///
    /// Uses ChaCha20Rng seeded from the OS CSPRNG, as specified in
    /// Section 2.1.1 of the protocol specification.
    pub fn generate() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        MasterSeed(seed)
    }

    /// Create a MasterSeed from existing bytes (e.g., restoring from backup).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterSeed(bytes)
    }

    /// Return the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode seed as hex string (placeholder for BIP-39 mnemonic).
    pub fn to_mnemonic_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Ed25519 keypair for authorizing spends (signing transactions).
///
/// The spend private key `x` signs ring signatures and computes
/// key images `I = x * H_p(P)`. The public key is embedded in
/// the Waecan address.
pub struct SpendKeypair {
    /// Private scalar (clamped per Ed25519 spec).
    pub private: Scalar,
    /// Public point: `private * G`.
    pub public: EdwardsPoint,
}

/// Ed25519 keypair for scanning blockchain outputs.
///
/// The view private key `v` detects owned outputs via the stealth
/// address protocol. Sharing it grants read-only access to
/// transaction history (e.g., for auditors).
pub struct ViewKeypair {
    /// Private scalar (clamped per Ed25519 spec).
    pub private: Scalar,
    /// Public point: `private * G`.
    pub public: EdwardsPoint,
}

/// Clamp a 32-byte key per Ed25519 spec: clear 3 low bits of byte 0,
/// clear high bit and set second-highest bit of byte 31.
fn clamp_ed25519(key: &mut [u8; 32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

/// Derive spend and view keypairs from a master seed.
///
/// Uses HMAC-SHA512 with domain-separated keys:
/// - Spend key: `HMAC-SHA512(b"waecnan-spend-v1", seed)`
/// - View key:  `HMAC-SHA512(b"waecnan-view-v1", seed)`
///
/// Both outputs are clamped per Ed25519 spec (Section 2.1.2).
pub fn derive_keypairs(seed: &MasterSeed) -> Result<(SpendKeypair, ViewKeypair), CryptoError> {
    let spend = derive_single_keypair(seed, b"waecnan-spend-v1")?;
    let view = derive_single_keypair(seed, b"waecnan-view-v1")?;
    Ok((
        SpendKeypair {
            private: spend.0,
            public: spend.1,
        },
        ViewKeypair {
            private: view.0,
            public: view.1,
        },
    ))
}

/// Derive a single keypair from seed using HMAC-SHA512 with a domain tag.
fn derive_single_keypair(
    seed: &MasterSeed,
    domain: &[u8],
) -> Result<(Scalar, EdwardsPoint), CryptoError> {
    let mut mac = HmacSha512::new_from_slice(domain)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(seed.as_bytes());
    let result = mac.finalize().into_bytes();

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result[..32]);
    clamp_ed25519(&mut key_bytes);

    let private = Scalar::from_bytes_mod_order(key_bytes);
    let public = private * ED25519_BASEPOINT_POINT;

    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_seed_generation() {
        let seed = MasterSeed::generate();
        assert_ne!(seed.0, [0u8; 32]);
    }

    #[test]
    fn test_derive_keypairs_deterministic() {
        let seed = MasterSeed::from_bytes([1u8; 32]);
        let (s1, v1) = derive_keypairs(&seed).unwrap();
        let (s2, v2) = derive_keypairs(&seed).unwrap();
        assert_eq!(s1.private, s2.private);
        assert_eq!(s1.public, s2.public);
        assert_eq!(v1.private, v2.private);
        assert_eq!(v1.public, v2.public);
    }

    #[test]
    fn test_spend_and_view_keys_differ() {
        let seed = MasterSeed::from_bytes([1u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        assert_ne!(spend.private, view.private);
        assert_ne!(spend.public, view.public);
    }

    #[test]
    fn test_public_matches_private() {
        let seed = MasterSeed::from_bytes([7u8; 32]);
        let (spend, view) = derive_keypairs(&seed).unwrap();
        assert_eq!(spend.public, spend.private * ED25519_BASEPOINT_POINT);
        assert_eq!(view.public, view.private * ED25519_BASEPOINT_POINT);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let (s_a, _) = derive_keypairs(&MasterSeed::from_bytes([1u8; 32])).unwrap();
        let (s_b, _) = derive_keypairs(&MasterSeed::from_bytes([2u8; 32])).unwrap();
        assert_ne!(s_a.private, s_b.private);
    }

    #[test]
    fn test_mnemonic_hex_length() {
        let seed = MasterSeed::from_bytes([0xAB; 32]);
        assert_eq!(seed.to_mnemonic_hex().len(), 64);
    }
}
