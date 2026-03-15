pub const BLOCK_TIME_TARGET: i64 = 120;
pub const ASERT_HALFLIFE: i64 = 86_400;

pub fn asert_next_target(
    anchor_bits: u64,
    anchor_height: u64,
    anchor_timestamp: u64,
    prev_height: u64,
    prev_timestamp: u64,
) -> u64 {
    let height_diff = (prev_height - anchor_height) as i64;
    let time_diff = prev_timestamp as i64 - anchor_timestamp as i64;
    let exponent = (time_diff - BLOCK_TIME_TARGET * height_diff)
        .wrapping_mul(1 << 16)
        / ASERT_HALFLIFE;
    asert_compute_target(anchor_bits, exponent)
}

fn asert_compute_target(anchor_bits: u64, exponent: i64) -> u64 {
    // Convert compact bits to 256-bit target using i128
    // Shift anchor target by 2^(exponent/65536)
    // Return as compact bits
    // Use i128 only. Zero f64.
    let anchor_target = bits_to_target(anchor_bits);
    let (shift, frac) = (exponent >> 16, exponent & 0xFFFF);
    // Apply integer approximation of 2^(frac/65536)
    // numerator = 65536 + frac, denominator = 65536
    let new_target = if shift >= 0 {
        (anchor_target as i128)
            .wrapping_mul((65536 + frac) as i128)
            .wrapping_shr(16)
            .wrapping_shl(shift as u32)
    } else {
        (anchor_target as i128)
            .wrapping_mul((65536 + frac) as i128)
            .wrapping_shr(16)
            .wrapping_shr((-shift) as u32)
    };
    target_to_bits(new_target.max(1) as u64)
}

pub fn bits_to_target(bits: u64) -> u64 {
    let exponent = (bits >> 24) as u32;
    let mantissa = bits & 0x00FF_FFFF;
    if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        mantissa << (8 * (exponent - 3))
    }
}

pub fn target_to_bits(target: u64) -> u64 {
    let mut size = 8u64;
    let mut compact = target;
    while size > 1 && compact >> (8 * (size - 1)) == 0 {
        size -= 1;
    }
    let mantissa = compact >> (8 * (size - 3).max(0));
    (size << 24) | (mantissa & 0x00FF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asert_anchor() {
        let anchor_bits = 0x200000FF; // Example initial difficulty target
        let anchor_height = 0;
        let anchor_timestamp = 1600000000;
        
        let prev_height = anchor_height + 1;
        let time_diff = BLOCK_TIME_TARGET;
        let prev_timestamp = anchor_timestamp + time_diff as u64;

        let new_target = asert_next_target(
            anchor_bits,
            anchor_height,
            anchor_timestamp,
            prev_height,
            prev_timestamp,
        );
        
        // Exact on-time block means difficulty does not change
        assert_eq!(new_target, anchor_bits);
    }

    #[test]
    fn test_asert_2x_fast() {
        let anchor_bits = 0x1d00ffff;
        let anchor_height = 0;
        let anchor_timestamp = 1600000000;
        
        let prev_height = 720;
        // Mined in exactly half the target time (720 blocks * 60 seconds)
        let time_diff = 720 * (BLOCK_TIME_TARGET / 2) as u64;
        let prev_timestamp = anchor_timestamp + time_diff;

        let new_target = asert_next_target(
            anchor_bits,
            anchor_height,
            anchor_timestamp,
            prev_height,
            prev_timestamp,
        );
        
        // 2x faster block production -> difficulty increases -> target shrinks
        assert!(new_target < anchor_bits);
    }

    #[test]
    fn test_asert_2x_slow() {
        let anchor_bits = 0x1d00ffff;
        let anchor_height = 0;
        let anchor_timestamp = 1600000000;
        
        let prev_height = 720;
        // Mined in exactly twice the target time (720 blocks * 240 seconds)
        let time_diff = 720 * (BLOCK_TIME_TARGET * 2) as u64;
        let prev_timestamp = anchor_timestamp + time_diff;

        let new_target = asert_next_target(
            anchor_bits,
            anchor_height,
            anchor_timestamp,
            prev_height,
            prev_timestamp,
        );
        
        // 2x slower block production -> difficulty drops -> target expands
        let anchor_expanded = bits_to_target(anchor_bits);
        let new_expanded = bits_to_target(new_target);
        assert!(new_expanded > anchor_expanded);
    }
}
