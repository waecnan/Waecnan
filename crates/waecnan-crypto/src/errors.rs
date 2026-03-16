//! Error types for the waecnan-crypto crate.

use thiserror::Error;

/// Errors that can occur in cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The ring does not have exactly 11 members.
    #[error("invalid ring size: expected 11, got {0}")]
    InvalidRingSize(usize),

    /// The ring signature verification failed.
    #[error("ring signature verification failed")]
    InvalidRingSignature,

    /// A key image has been seen before (double-spend attempt).
    #[error("duplicate key image detected")]
    DuplicateKeyImage,

    /// The Pedersen commitment balance check failed.
    #[error("commitment balance check failed: inputs != outputs + fee")]
    BalanceMismatch,

    /// The Bulletproof range proof is invalid.
    #[error("invalid range proof")]
    InvalidRangeProof,

    /// Bech32m address encoding/decoding error.
    #[error("address error: {0}")]
    AddressError(String),

    /// Invalid Ed25519 public key (identity or low-order point).
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// HMAC key derivation failed.
    #[error("key derivation error: {0}")]
    KeyDerivationError(String),

    /// Generic cryptographic error.
    #[error("crypto error: {0}")]
    Other(String),
}
