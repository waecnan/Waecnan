use tiny_keccak::{Hasher, Keccak};
use waecnan_core::block::{block_reward, Block, BlockHeader, CoinbaseTx};
use waecnan_core::pow::{compute_pow, is_pow_valid};
use waecnan_core::transaction::Transaction;

/// Miner configuration.
pub struct MinerConfig {
    /// Number of mining threads (1..=num_cpus).
    pub threads: usize,
    /// Bech32m address to receive block rewards.
    pub miner_address: String,
}

/// A block template ready to be mined.
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub coinbase: CoinbaseTx,
    pub transactions: Vec<Transaction>,
}

/// Build a block template for mining.
pub fn build_block_template(
    prev_hash: [u8; 32],
    height: u64,
    timestamp: u64,
    difficulty_bits: u64,
    transactions: Vec<Transaction>,
    miner_output_key: curve25519_dalek::edwards::CompressedEdwardsY,
) -> BlockTemplate {
    let reward = block_reward(height);

    let coinbase = CoinbaseTx {
        height,
        reward,
        miner_output_key,
        genesis_message: vec![],
    };

    // Build Merkle root from coinbase + transactions
    let mut tx_hashes = vec![hash_coinbase(&coinbase)];
    for tx in &transactions {
        tx_hashes.push(hash_transaction(tx));
    }
    let merkle_root = compute_merkle_root(&tx_hashes);

    let header = BlockHeader {
        version: 1,
        prev_hash,
        merkle_root,
        timestamp,
        difficulty: difficulty_bits,
        nonce: 0,
        height,
    };

    BlockTemplate {
        header,
        coinbase,
        transactions,
    }
}

/// Mine a block by incrementing the nonce until PoW is valid.
pub fn mine_block(mut template: BlockTemplate, seed_hash: [u8; 32]) -> Block {
    loop {
        template.header.nonce += 1;
        let pow_hash = compute_pow(&template.header, &seed_hash);
        if is_pow_valid(&template.header, &pow_hash) {
            return Block {
                header: template.header,
                coinbase: template.coinbase,
                transactions: template.transactions,
            };
        }
        if template.header.nonce % 100_000 == 0 {
            eprintln!(
                "[miner] nonce={} hash={:02x}{:02x}{:02x}{:02x}...",
                template.header.nonce,
                pow_hash[31], pow_hash[30], pow_hash[29], pow_hash[28]
            );
        }
    }
}

/// Compute a Merkle root over a list of transaction hashes using Keccak-256.
/// Empty list returns [0u8; 32].
pub fn compute_merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    if tx_hashes.len() == 1 {
        return tx_hashes[0];
    }
    let mut level: Vec<[u8; 32]> = tx_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let mut hasher = Keccak::v256();
            hasher.update(&pair[0]);
            if pair.len() == 2 {
                hasher.update(&pair[1]);
            } else {
                hasher.update(&pair[0]);
            }
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            next.push(out);
        }
        level = next;
    }
    level[0]
}

/// Hash a coinbase transaction for Merkle tree inclusion.
fn hash_coinbase(cb: &CoinbaseTx) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&cb.height.to_le_bytes());
    hasher.update(&cb.reward.to_le_bytes());
    hasher.update(cb.miner_output_key.as_bytes());
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Hash a transaction for Merkle tree inclusion.
fn hash_transaction(tx: &Transaction) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&[tx.version]);
    hasher.update(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        hasher.update(input.key_image.as_bytes());
    }
    hasher.update(&(tx.outputs.len() as u32).to_le_bytes());
    for output in &tx.outputs {
        hasher.update(output.output_key.as_bytes());
    }
    hasher.update(&tx.fee.to_le_bytes());
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use waecnan_core::pow::get_seed_hash;
    use waecnan_core::transaction::ATOMIC_UNITS_PER_WAEC;

    #[test]
    fn test_build_block_template_height_and_reward() {
        let miner_key = ED25519_BASEPOINT_POINT.compress();
        let template =
            build_block_template([0u8; 32], 0, 1_700_000_000, 0x2007_FFFF, vec![], miner_key);
        assert_eq!(template.header.height, 0);
        assert_eq!(template.coinbase.reward, 50 * ATOMIC_UNITS_PER_WAEC);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(compute_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let txid = [42u8; 32];
        assert_eq!(compute_merkle_root(&[txid]), txid);
    }

    #[test]
    fn test_merkle_root_two_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let root1 = compute_merkle_root(&[a, b]);
        let root2 = compute_merkle_root(&[a, b]);
        assert_eq!(root1, root2);
        // Different order produces different root
        let root3 = compute_merkle_root(&[b, a]);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_mine_block_difficulty_1() {
        let miner_key = ED25519_BASEPOINT_POINT.compress();
        let template = build_block_template(
            [0u8; 32],
            0,
            1_700_000_000,
            0x2007_FFFF, // easy compact target
            vec![],
            miner_key,
        );
        let seed_hash = get_seed_hash(0, [0u8; 32]);
        let block = mine_block(template, seed_hash);
        let pow_hash = compute_pow(&block.header, &seed_hash);
        assert!(is_pow_valid(&block.header, &pow_hash));
    }
}
