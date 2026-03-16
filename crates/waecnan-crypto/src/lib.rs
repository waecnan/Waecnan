//! # Waecan Crypto
//!
//! Cryptographic primitives for the Waecan protocol:
//! - Key derivation (master seed, spend/view keypairs)
//! - Stealth addresses (one-time output keys)
//! - Ring signatures (MLSAG)
//! - Pedersen commitments (confidential amounts)
//! - Bech32m address encoding

pub mod address;
pub mod errors;
pub mod hash;
pub mod keys;
pub mod pedersen;
pub mod ring_sig;
pub mod stealth;
