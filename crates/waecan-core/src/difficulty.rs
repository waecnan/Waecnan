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
    let solvetime_diff = time_diff - BLOCK_TIME_TARGET * height_diff;

    if solvetime_diff == 0 {
        return anchor_bits;
    }

    let anchor_target = compact_to_u128(anchor_bits);
    let new_target = asert_shift(anchor_target, solvetime_diff);
    u128_to_compact(new_target.max(1))
}

fn asert_shift(anchor: u128, solvetime_diff: i64) -> u128 {
    let halflife = ASERT_HALFLIFE as i128;
    let diff = solvetime_diff as i128;

    if diff > 0 {
        let whole_shifts = diff / halflife;
        let remainder = diff % halflife;
        let scaled = anchor
            .saturating_mul((halflife + remainder) as u128)
            / halflife as u128;
        if whole_shifts >= 128 {
            u128::MAX
        } else {
            let shift = whole_shifts as u32;
            if scaled.leading_zeros() < shift {
                u128::MAX
            } else {
                scaled << shift
            }
        }
    } else {
        let diff_abs = -diff;
        let whole_shifts = diff_abs / halflife;
        let remainder = diff_abs % halflife;
        let scaled = anchor
            .saturating_mul((halflife - remainder) as u128)
            / halflife as u128;
        if whole_shifts >= 128 {
            1u128
        } else {
            (scaled >> whole_shifts as u32).max(1)
        }
    }
}

pub fn compact_to_u128(bits: u64) -> u128 {
    let exponent = (bits >> 24) as u32;
    let mantissa = (bits & 0x007F_FFFF) as u128;
    if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        let shift = 8 * (exponent - 3);
        if shift >= 128 {
            u128::MAX
        } else {
            mantissa << shift
        }
    }
}

pub fn u128_to_compact(target: u128) -> u64 {
    if target == 0 {
        return 0;
    }
    let bits_needed = 128 - target.leading_zeros();
    let exponent = bits_needed.div_ceil(8);
    let mantissa = if exponent <= 3 {
        (target << (8 * (3 - exponent))) as u64
    } else {
        let shift = 8 * (exponent - 3);
        if shift >= 128 {
            0u64
        } else {
            (target >> shift) as u64
        }
    };
    ((exponent as u64) << 24) | (mantissa & 0x007F_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR_BITS: u64 = 0x0D0F_0000;

    #[test]
    fn test_asert_anchor() {
        let result = asert_next_target(
            ANCHOR_BITS, 0, 0, 1, BLOCK_TIME_TARGET as u64,
        );
        assert_eq!(result, ANCHOR_BITS);
    }

    #[test]
    fn test_asert_2x_fast() {
        // 720 blocks in half the expected time → difficulty increases → target decreases
        let blocks: u64 = 720;
        let result = asert_next_target(
            ANCHOR_BITS, 0, 0,
            blocks,
            blocks * (BLOCK_TIME_TARGET as u64) / 2,
        );
        let result_target = compact_to_u128(result);
        let anchor_target = compact_to_u128(ANCHOR_BITS);
        assert!(result_target < anchor_target,
            "2x fast: target should decrease. got {} anchor {}",
            result_target, anchor_target);
    }

    #[test]
    fn test_asert_2x_slow() {
        // 720 blocks in double the expected time → difficulty decreases → target increases
        let blocks: u64 = 720;
        let result = asert_next_target(
            ANCHOR_BITS, 0, 0,
            blocks,
            blocks * (BLOCK_TIME_TARGET as u64) * 2,
        );
        let result_target = compact_to_u128(result);
        let anchor_target = compact_to_u128(ANCHOR_BITS);
        assert!(result_target > anchor_target,
            "2x slow: target should increase. got {} anchor {}",
            result_target, anchor_target);
    }
}
