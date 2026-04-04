use crate::block::BlockHeader;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

/// Convert compact (nBits) difficulty to a 32-byte big-endian target.
/// Format: top byte = exponent (number of significant bytes), lower 3 bytes = mantissa.
/// target = mantissa * 2^(8 * (exponent - 3))
pub fn compact_to_target_bytes(bits: u64) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007F_FFFF;
    let mut target = [0u8; 32];
    if exponent == 0 || exponent > 32 {
        return target;
    }
    // Write mantissa as 3 bytes at position (32 - exponent)
    let pos = 32usize.saturating_sub(exponent);
    if pos + 2 < 32 {
        target[pos] = ((mantissa >> 16) & 0xff) as u8;
    }
    if pos + 1 < 32 {
        target[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
    }
    if pos + 2 <= 32 {
        target[pos + 2] = (mantissa & 0xff) as u8;
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
    // Convert compact bits to 32-byte target (big-endian 256-bit)
    let target = compact_to_target_bytes(header.difficulty);
    // Compare hash <= target byte by byte (big-endian)
    pow_hash <= &target
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
        let hash = [0x01; 32]; // any small hash should pass
        assert!(is_pow_valid(&header, &hash));
    }

    #[test]
    fn test_is_pow_valid_fails_hard_target() {
        // 0x0100_0001: exponent=1, mantissa=1 → target byte[31]=0x01, rest 0x00
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
    fn test_compact_to_target_bytes_easy() {
        // 0x2007FFFF: exponent=32, mantissa=0x07FFFF
        // pos = 32 - 32 = 0, so target[0]=0x07, target[1]=0xFF, target[2]=0xFF
        let target = compact_to_target_bytes(0x2007_FFFF);
        assert_eq!(target[0], 0x07);
        assert_eq!(target[1], 0xFF);
        assert_eq!(target[2], 0xFF);
        // rest should be zero
        for i in 3..32 {
            assert_eq!(target[i], 0, "byte {} should be 0", i);
        }
    }
}
