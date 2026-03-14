use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::PublicKey;
use waecan_crypto::pedersen::PedersenCommitment;
use waecan_crypto::ring_sig::{Ring, RingSignature};

pub const ATOMIC_UNITS_PER_WAEC: u64 = 1_000_000_000_000;
pub const MIN_FEE_ATOMIC: u64 = 1_000_000_000;
pub const MAX_SUPPLY_ATOMIC: u128 = 105_000_000 * ATOMIC_UNITS_PER_WAEC as u128;

/// A Waecan transaction moving funds between confidential stealth addresses.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Currently 1
    pub version: u8,
    /// Vector of spent inputs, shielded by ring signatures
    pub inputs: Vec<TransactionInput>,
    /// Vector of created outputs, shielded by stealth addresses and Pedersen commitments
    pub outputs: Vec<TransactionOutput>,
    /// Publicly verifiable transaction fee in atomic units (destroyed, not paid to miner)
    pub fee: u64,
    /// Transaction public key `R` for stealth address derivation
    pub tx_public_key: PublicKey,
    /// Optional extra data, max 255 bytes
    pub extra: Vec<u8>,
}

impl Transaction {
    /// Returns the exact size in bytes this transaction would occupy when serialized.
    /// This is used to enforce the 100,000 byte consensus limit (Rule 9).
    pub fn serialized_size(&self) -> usize {
        let mut size = 0;
        size += 1; // version (u8)
        size += 4; // inputs len prefix (u32)
        size += 4; // outputs len prefix (u32)
        size += 8; // fee (u64)
        size += 32; // tx_public_key (Ed25519 point)
        size += 4 + self.extra.len(); // extra len prefix (u32) + extra bytes

        // Each Input:
        // ring: 11 members * 32 bytes = 352
        // key_image: 32 bytes
        // ring_sig: 32 (key_image) + 32 (c_0) + (11 * 32) (s) = 416
        // pseudo_commit: 32 bytes
        // Total per input = 832 bytes
        size += self.inputs.len() * 832;

        // Each Output:
        // output_key: 32 bytes
        // commitment: 32 bytes
        // range_proof prefix: 4 bytes
        // range_proof bytes: len
        // encrypted_amount: 8 bytes
        for out in &self.outputs {
            size += 32 + 32 + 4 + out.range_proof.len() + 8;
        }

        size
    }
}

/// An input to a transaction, hiding the real spent output among decoys.
#[derive(Clone, Debug)]
pub struct TransactionInput {
    /// Exactly 11 ring members (1 real + 10 decoys)
    pub ring: Ring,
    /// Unique identifier preventing double-spend of the real input
    pub key_image: CompressedEdwardsY,
    /// MLSAG signature authorizing the spend and proving balancing
    pub ring_sig: RingSignature,
    /// Pedersen commitment shielding the input amount
    pub pseudo_commit: PedersenCommitment,
}

/// An output created by a transaction.
#[derive(Clone, Debug)]
pub struct TransactionOutput {
    /// Recipient's one-time stealth address public key `P`
    pub output_key: PublicKey,
    /// Pedersen commitment shielding the output amount
    pub commitment: PedersenCommitment,
    /// Bulletproof proving the amount is in [0, 2^64)
    /// (Stubbed as Vec<u8> pending `bulletproofs` v4.0 crate integration)
    pub range_proof: Vec<u8>,
    /// Amount encrypted for the recipient's view key (8 bytes)
    pub encrypted_amount: [u8; 8],
}
