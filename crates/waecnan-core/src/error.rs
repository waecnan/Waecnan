use thiserror::Error;

/// Core protocol validation errors.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Transaction version must be 1")]
    InvalidVersion,
    #[error("Transaction must have at least 1 input")]
    NoInputs,
    #[error("Transaction must have 1 to 16 outputs")]
    InvalidOutputCount,
    #[error("Transaction fee below minimum")]
    InsufficientFee,
    #[error("Ring size must be exactly 11")]
    InvalidRingSize,
    #[error("Key image already spent")]
    DoubleSpend,
    #[error("Invalid MLSAG ring signature")]
    InvalidRingSignature,
    #[error("Invalid Bulletproof range proof")]
    InvalidRangeProof,
    #[error("Inputs do not balance with outputs and fee")]
    BalanceMismatch,
    #[error("Transaction exceeds maximum serialized size")]
    TooLarge,
    #[error("Transaction extra field exceeds 255 bytes")]
    ExtraTooLarge,
    #[error("Transaction public key is invalid")]
    InvalidTxPublicKey,
    #[error("Block header version must be 1")]
    InvalidBlockVersion,
    #[error("Block prev_hash does not match chain tip")]
    InvalidPrevHash,
    #[error("Block timestamp not greater than median of last 11 blocks")]
    TimestampTooOld,
    #[error("Block timestamp too far in the future")]
    TimestampTooNew,
    #[error("Block difficulty does not match expected ASERT target")]
    InvalidDifficulty,
    #[error("Block PoW hash exceeds target")]
    InvalidPoW,
    #[error("Block merkle root mismatch")]
    InvalidMerkleRoot,
    #[error("Coinbase reward does not match expected block reward")]
    InvalidCoinbaseReward,
    #[error("Block contains invalid transaction")]
    InvalidBlockTransaction(String),
    #[error("Duplicate key image within block")]
    DuplicateKeyImageInBlock,
}
