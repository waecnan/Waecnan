use crate::error::StorageError;
use curve25519_dalek::edwards::CompressedEdwardsY;
use waecnan_crypto::pedersen::PedersenCommitment;

/// UTXO record stored in CF_UTXO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRecord {
    pub output_key: CompressedEdwardsY, // 32 bytes
    pub commitment: PedersenCommitment, // 32 bytes
    pub height: u64,                    // 8 bytes
    pub tx_hash: [u8; 32],              // 32 bytes
    pub output_index: u8,               // 1 byte
}

impl OutputRecord {
    /// Serialize deterministically to exactly 105 bytes.
    pub fn serialize(&self) -> [u8; 105] {
        let mut buf = [0u8; 105];
        buf[0..32].copy_from_slice(self.output_key.as_bytes());
        buf[32..64].copy_from_slice(self.commitment.commitment.as_bytes());
        buf[64..72].copy_from_slice(&self.height.to_le_bytes());
        buf[72..104].copy_from_slice(&self.tx_hash);
        buf[104] = self.output_index;
        buf
    }

    /// Deserialize from 105 bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != 105 {
            return Err(StorageError::RecordSizeMismatch);
        }

        // Use from_slice safely (from_slice expects 32 bytes always, no unwraps needed on correct length if it fails later)
        let output_key =
            CompressedEdwardsY::from_slice(&bytes[0..32]).map_err(|_| StorageError::InvalidKey)?;
        let commit_point =
            CompressedEdwardsY::from_slice(&bytes[32..64]).map_err(|_| StorageError::InvalidKey)?;

        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&bytes[64..72]);
        let height = u64::from_le_bytes(height_bytes);

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&bytes[72..104]);

        Ok(Self {
            output_key,
            commitment: PedersenCommitment {
                commitment: commit_point,
            },
            height,
            tx_hash,
            output_index: bytes[104],
        })
    }
}
