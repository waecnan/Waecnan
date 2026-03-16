use crate::block::BlockHeader;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

#[allow(clippy::needless_range_loop)]
pub fn compact_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xFF; 32];
    }
    let divisor = difficulty as u128;
    let mut quotient_be = [0u8; 32];
    let mut remainder: u128 = 0;
    for i in 0..32 {
        remainder = (remainder << 8) | 0xFF;
        quotient_be[i] = (remainder / divisor) as u8;
        remainder %= divisor;
    }
    let mut target = [0u8; 32];
    for i in 0..32 {
        target[i] = quotient_be[31 - i];
    }
    target
}

pub fn compute_pow(header: &BlockHeader, seed_hash: &[u8; 32]) -> [u8; 32] {
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, seed_hash).expect("RandomX cache init failed");
    let vm = RandomXVM::new(flags, Some(cache), None).expect("RandomX VM init failed");
    let input = header.serialize();
    let hash = vm.calculate_hash(&input).expect("RandomX hash failed");
    hash.try_into().unwrap()
}

pub fn is_pow_valid(header: &BlockHeader, pow_hash: &[u8; 32]) -> bool {
    let target = compact_to_target(header.difficulty);
    for i in (0..32).rev() {
        if pow_hash[i] < target[i] {
            return true;
        } else if pow_hash[i] > target[i] {
            return false;
        }
    }
    true
}

pub fn get_seed_hash(height: u64, genesis_hash: [u8; 32]) -> [u8; 32] {
    let _seed_height = height - (height % 2048);
    genesis_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pow_valid_passes() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty: 1,
            nonce: 0,
            height: 0,
        };
        let hash = [0xFF; 32];
        assert!(is_pow_valid(&header, &hash));
    }

    #[test]
    fn test_is_pow_valid_fails() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty: u64::MAX,
            nonce: 0,
            height: 0,
        };
        let hash = [0xFF; 32];
        assert!(!is_pow_valid(&header, &hash));
    }
}
