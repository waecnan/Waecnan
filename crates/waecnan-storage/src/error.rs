use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    DbError(#[from] rocksdb::Error),

    #[error("OutputRecord size mismatch, expected 105 bytes")]
    RecordSizeMismatch,

    #[error("Invalid Ed25519 key bytes in record")]
    InvalidKey,

    #[error("Block not found")]
    BlockNotFound,

    #[error("Missing CF: {0}")]
    MissingColumnFamily(&'static str),

    #[error("Failed to serialize block")]
    SerializationError,
}
