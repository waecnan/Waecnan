use crate::block::{Block, BlockHeader, CoinbaseTx};
use curve25519_dalek::edwards::CompressedEdwardsY;

pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];
pub const GENESIS_HEIGHT: u64 = 0;
pub const GENESIS_TIMESTAMP: u64 = 1742000000; // 2025-03-15 UTC approx
pub const GENESIS_BITS: u64 = 0x2007_FFFF;     // low difficulty for launch
pub const GENESIS_NONCE: u64 = 0;              // will be found by miner

/// The genesis message embedded in the coinbase extra field.
/// SHA-256 of the Wæcnan whitepaper — placeholder until whitepaper is final.
pub const GENESIS_MESSAGE: &[u8] = b"Waecnan: Privacy is not a privilege. 2025-03-15";

/// Build the Waecan genesis block.
pub fn build_genesis_block(_miner_address: &str) -> Block {
    let header = BlockHeader {
        version:    1,
        prev_hash:  GENESIS_PREV_HASH,
        merkle_root: [0u8; 32],
        timestamp:  GENESIS_TIMESTAMP,
        difficulty: GENESIS_BITS,
        nonce:      GENESIS_NONCE,
        height:     GENESIS_HEIGHT,
    };

    let coinbase = CoinbaseTx {
        height: GENESIS_HEIGHT,
        reward: 0, // No pre-mine
        miner_output_key: CompressedEdwardsY::default(), // Subbed out, address ignored for pure genesis
        genesis_message: GENESIS_MESSAGE.to_vec(),
    };

    Block {
        header,
        coinbase,
        transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_height_is_zero() {
        let block = build_genesis_block("dummy");
        assert_eq!(block.header.height, 0);
        assert_eq!(block.coinbase.height, 0);
    }

    #[test]
    fn test_genesis_prev_hash_is_zero() {
        let block = build_genesis_block("dummy");
        assert_eq!(block.header.prev_hash, [0u8; 32]);
    }

    #[test]
    fn test_genesis_timestamp() {
        let block = build_genesis_block("dummy");
        assert_eq!(block.header.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn test_genesis_difficulty() {
        let block = build_genesis_block("dummy");
        assert_eq!(block.header.difficulty, GENESIS_BITS);
    }

    #[test]
    fn test_genesis_message_contains_waecnan() {
        let msg = String::from_utf8_lossy(GENESIS_MESSAGE);
        assert!(msg.contains("Waecnan"));
    }
}
