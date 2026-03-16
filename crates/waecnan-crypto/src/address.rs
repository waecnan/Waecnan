//! Bech32m address encoding and decoding for Waecan addresses.
//!
//! A Waecan address encodes spend + view public keys using Bech32m
//! with prefix `wae1` (mainnet) or `waet1` (testnet). Per spec
//! Section 2.2.1.

use bech32::{Bech32m, Hrp};
use curve25519_dalek::edwards::EdwardsPoint;

use crate::errors::CryptoError;

/// Mainnet address prefix.
pub const MAINNET_PREFIX: &str = "wae";
/// Testnet address prefix.
pub const TESTNET_PREFIX: &str = "waet";

/// A Waecan address containing the spend and view public keys.
///
/// Encoded as Bech32m: `wae1` + bech32m(spend_pub || view_pub).
/// Total length is approximately 109 characters.
#[derive(Clone, Debug)]
pub struct WaecanAddress {
    /// Spend public key (32 bytes). Used in stealth address derivation.
    pub spend_public: EdwardsPoint,
    /// View public key (32 bytes). Used to scan for owned outputs.
    pub view_public: EdwardsPoint,
}

impl WaecanAddress {
    /// Encode the address as a mainnet Bech32m string.
    pub fn to_bech32m(&self) -> Result<String, CryptoError> {
        self.to_bech32m_with_prefix(MAINNET_PREFIX)
    }

    /// Encode the address with a custom prefix.
    pub fn to_bech32m_with_prefix(&self, prefix: &str) -> Result<String, CryptoError> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(self.spend_public.compress().as_bytes());
        payload.extend_from_slice(self.view_public.compress().as_bytes());

        let hrp = Hrp::parse(prefix)
            .map_err(|e| CryptoError::AddressError(format!("invalid HRP: {}", e)))?;
        bech32::encode::<Bech32m>(hrp, &payload)
            .map_err(|e| CryptoError::AddressError(format!("encode error: {}", e)))
    }

    /// Decode a Waecan address from a Bech32m string.
    pub fn from_bech32m(address: &str) -> Result<Self, CryptoError> {
        let (hrp, data) = bech32::decode(address)
            .map_err(|e| CryptoError::AddressError(format!("decode error: {}", e)))?;

        let prefix = hrp.to_string();
        if prefix != MAINNET_PREFIX && prefix != TESTNET_PREFIX {
            return Err(CryptoError::AddressError(format!(
                "unknown prefix: {}",
                prefix
            )));
        }

        if data.len() != 64 {
            return Err(CryptoError::AddressError(format!(
                "invalid payload length: expected 64, got {}",
                data.len()
            )));
        }

        let mut spend_bytes = [0u8; 32];
        let mut view_bytes = [0u8; 32];
        spend_bytes.copy_from_slice(&data[..32]);
        view_bytes.copy_from_slice(&data[32..64]);

        let spend_compressed =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_bytes)
                .map_err(|e| CryptoError::AddressError(format!("invalid spend key: {}", e)))?;
        let view_compressed =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&view_bytes)
                .map_err(|e| CryptoError::AddressError(format!("invalid view key: {}", e)))?;

        let spend_public = spend_compressed.decompress().ok_or_else(|| {
            CryptoError::InvalidPublicKey("spend key decompression failed".into())
        })?;
        let view_public = view_compressed
            .decompress()
            .ok_or_else(|| CryptoError::InvalidPublicKey("view key decompression failed".into()))?;

        Ok(WaecanAddress {
            spend_public,
            view_public,
        })
    }

    /// Check if an address string is a testnet address.
    pub fn is_testnet(address: &str) -> bool {
        address.starts_with(TESTNET_PREFIX)
    }
}

impl PartialEq for WaecanAddress {
    fn eq(&self, other: &Self) -> bool {
        self.spend_public.compress() == other.spend_public.compress()
            && self.view_public.compress() == other.view_public.compress()
    }
}

impl Eq for WaecanAddress {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_keypairs, MasterSeed};

    fn test_addr() -> WaecanAddress {
        let (s, v) = derive_keypairs(&MasterSeed::from_bytes([42u8; 32])).unwrap();
        WaecanAddress {
            spend_public: s.public,
            view_public: v.public,
        }
    }

    #[test]
    fn test_roundtrip() {
        let addr = test_addr();
        let encoded = addr.to_bech32m().unwrap();
        assert!(encoded.starts_with("wae1"));
        assert_eq!(addr, WaecanAddress::from_bech32m(&encoded).unwrap());
    }

    #[test]
    fn test_testnet_roundtrip() {
        let addr = test_addr();
        let encoded = addr.to_bech32m_with_prefix(TESTNET_PREFIX).unwrap();
        assert!(encoded.starts_with("waet1"));
        assert!(WaecanAddress::is_testnet(&encoded));
        assert_eq!(addr, WaecanAddress::from_bech32m(&encoded).unwrap());
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        let addr = test_addr();
        let encoded = addr.to_bech32m_with_prefix("btc").unwrap();
        assert!(WaecanAddress::from_bech32m(&encoded).is_err());
    }

    #[test]
    fn test_corrupted_data_rejected() {
        let addr = test_addr();
        let encoded = addr.to_bech32m().unwrap();
        let mut chars: Vec<char> = encoded.chars().collect();
        if let Some(c) = chars.get_mut(20) {
            *c = if *c == 'q' { 'p' } else { 'q' };
        }
        let corrupted: String = chars.into_iter().collect();
        assert!(WaecanAddress::from_bech32m(&corrupted).is_err());
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let (s_a, v_a) = derive_keypairs(&MasterSeed::from_bytes([1u8; 32])).unwrap();
        let (s_b, v_b) = derive_keypairs(&MasterSeed::from_bytes([2u8; 32])).unwrap();
        let a = WaecanAddress {
            spend_public: s_a.public,
            view_public: v_a.public,
        };
        let b = WaecanAddress {
            spend_public: s_b.public,
            view_public: v_b.public,
        };
        assert_ne!(a.to_bech32m().unwrap(), b.to_bech32m().unwrap());
    }

    #[test]
    fn test_address_length() {
        let addr = test_addr();
        let len = addr.to_bech32m().unwrap().len();
        assert!(len > 100 && len < 120, "length {} out of range", len);
    }
}
