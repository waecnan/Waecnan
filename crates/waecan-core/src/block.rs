use crate::transaction::Transaction;
use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::transaction::ATOMIC_UNITS_PER_WAEC;

/// Header of a Waecan block, containing PoW metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u8,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Compact difficulty target
    pub difficulty: u64,
    pub nonce: u64,
    pub height: u64,
}

impl BlockHeader {
    /// Canonical serialization of the block header into exactly 97 bytes.
    /// Used for hashing in Proof of Work and identifying the block.
    pub fn serialize(&self) -> [u8; 97] {
        let mut buf = [0u8; 97];
        buf[0] = self.version;
        buf[1..33].copy_from_slice(&self.prev_hash);
        buf[33..65].copy_from_slice(&self.merkle_root);
        buf[65..73].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[73..81].copy_from_slice(&self.difficulty.to_le_bytes());
        buf[81..89].copy_from_slice(&self.nonce.to_le_bytes());
        buf[89..97].copy_from_slice(&self.height.to_le_bytes());
        buf
    }
}

/// A Waecan block containing a list of transactions.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    /// The miner's reward transaction without any inputs.
    pub coinbase: CoinbaseTx,
    pub transactions: Vec<Transaction>,
}

/// The first transaction in a block, generating the emission reward.
#[derive(Clone, Debug)]
pub struct CoinbaseTx {
    pub height: u64,
    pub reward: u64,
    pub miner_output_key: CompressedEdwardsY,
    /// Genesis message only used at height 0
    pub genesis_message: Vec<u8>,
}

/// Calculate the block reward for a given height.
/// Genesis block (height 0) pays 50 WAEC.
/// Halves every 525,600 blocks asymptotically over 2-year epochs.
pub fn block_reward(height: u64) -> u64 {
    let halvings = height / 525_600;

    // Once right-shifts exceed 63 on a u64, it might overflow or be zero
    // depending on architecture, but Rust allows checked_shr or we manually clamp
    if halvings >= 64 {
        return 0;
    }

    let base_reward = 50 * ATOMIC_UNITS_PER_WAEC;
    base_reward >> halvings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_header_97_bytes() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [2u8; 32],
            merkle_root: [3u8; 32],
            timestamp: 1680000000,
            difficulty: 100000,
            nonce: 42,
            height: 10,
        };

        let serialized = header.serialize();
        assert_eq!(serialized.len(), 97);

        assert_eq!(serialized[0], 1);
        assert_eq!(&serialized[1..33], &[2u8; 32]);
        assert_eq!(&serialized[33..65], &[3u8; 32]);
        assert_eq!(&serialized[65..73], &1680000000u64.to_le_bytes());
        assert_eq!(&serialized[73..81], &100000u64.to_le_bytes());
        assert_eq!(&serialized[81..89], &42u64.to_le_bytes());
        assert_eq!(&serialized[89..97], &10u64.to_le_bytes());
    }

    #[test]
    fn test_block_reward_schedule() {
        let base = 50 * ATOMIC_UNITS_PER_WAEC;

        // height: 0
        assert_eq!(block_reward(0), base);

        // height: 525_599 (just before first halving)
        assert_eq!(block_reward(525_599), base);

        // height: 525_600 (first halving, right shifted by 1)
        assert_eq!(block_reward(525_600), base >> 1);

        // height: 1_051_199 (just before second halving)
        assert_eq!(block_reward(1_051_199), base >> 1);

        // height: 1_051_200 (second halving, right shifted by 2)
        assert_eq!(block_reward(1_051_200), base >> 2);
    }
}
