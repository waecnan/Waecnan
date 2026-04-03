use crate::block::BlockHeader;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

/// Decode a compact (nBits) difficulty value into a 256-bit target.
/// Format: highest byte = exponent (number of bytes), lower 3 bytes = mantissa.
/// target = mantissa * 2^(8 * (exponent - 3))
/// Stored as little-endian [u8; 32].
pub fn compact_to_target(bits: u64) -> [u8; 32] {
    let exponent = ((bits >> 24) & 0xFF) as usize;
    let mantissa = (bits & 0x007F_FFFF) as u64;

    let mut target = [0u8; 32];
    if exponent == 0 {
        return target;
    }

    // Place mantissa bytes (big-endian, 3 bytes) at the correct position.
    // In LE layout, the MSB of the mantissa goes to byte index (exponent - 1).
    let mantissa_bytes = mantissa.to_be_bytes(); // 8 bytes, we want last 3
    for j in 0..3 {
        let byte_pos = exponent.saturating_sub(1 + j);
        if byte_pos < 32 {
            target[byte_pos] = mantissa_bytes[5 + j];
        }
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
    fn test_is_pow_valid_passes_easy_target() {
        // 0x2007FFFF: exponent=32, mantissa=0x07FFFF → near-max target (easiest)
        let header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty: 0x2007_FFFF,
            nonce: 0,
            height: 0,
        };
        let hash = [0xFF; 32];
        assert!(is_pow_valid(&header, &hash));
    }

    #[test]
    fn test_is_pow_valid_fails_hard_target() {
        // 0x0100_0001: exponent=1, mantissa=1 → target is 1 (nearly impossible)
        let header = BlockHeader {
            version: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty: 0x0100_0001,
            nonce: 0,
            height: 0,
        };
        let hash = [0xFF; 32];
        assert!(!is_pow_valid(&header, &hash));
    }

    #[test]
    fn test_compact_to_target_max_difficulty() {
        // 0x2007FFFF should produce a target with 0x07FFFF at bytes 29,30,31
        let target = compact_to_target(0x2007_FFFF);
        assert_eq!(target[31], 0x07);
        assert_eq!(target[30], 0xFF);
        assert_eq!(target[29], 0xFF);
    }
}
