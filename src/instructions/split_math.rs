use pinocchio::error::ProgramError;

use crate::error::ZupyTokenError;

/// Split result: (company_amount, burn_amount, incentive_amount)
#[derive(Debug)]
pub struct SplitResult {
    pub company_amount: u64,
    pub burn_amount: u64,
    pub incentive_amount: u64,
}

/// Calculate the 20% markup split for execute_split_transfer.
///
/// Given `z_total`, computes:
///   - z_base = (z_total * 100) / 120  (83.33% → company)
///   - z_markup = z_total - z_base
///   - burn_amount = z_markup / 2       (8.33%, floor)
///   - incentive_amount = z_markup - burn_amount  (8.33%, gets dust)
///
/// Uses u128 intermediate arithmetic to prevent overflow.
/// All u128→u64 casts use `try_into()` (NOT `as u64`) per Audit 12.1.
/// Sum verification via `checked_add` ensures no tokens are lost.
pub fn calculate_split(z_total: u64) -> Result<SplitResult, ProgramError> {
    if z_total == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }

    // u128 intermediate to prevent overflow on multiply
    let total_128 = z_total as u128;
    let z_base_128 = (total_128 * 100) / 120;

    // AUDIT 12.1 CRITICAL: u128→u64 via try_into(), NOT `as u64`
    let z_base: u64 = z_base_128
        .try_into()
        .map_err(|_| ZupyTokenError::SplitCalculationError)?;

    // z_markup = z_total - z_base (safe: z_base <= z_total by construction)
    let z_markup = z_total
        .checked_sub(z_base)
        .ok_or(ZupyTokenError::SplitCalculationError)?;

    let burn_amount = z_markup / 2; // floor division
    let incentive_amount = z_markup
        .checked_sub(burn_amount)
        .ok_or(ZupyTokenError::SplitCalculationError)?; // gets dust (ceil)

    let company_amount = z_base;

    // AUDIT 12.1 CRITICAL: Sum verification with checked_add
    let sum = company_amount
        .checked_add(burn_amount)
        .and_then(|s| s.checked_add(incentive_amount))
        .ok_or(ZupyTokenError::SplitCalculationError)?;

    if sum != z_total {
        return Err(ZupyTokenError::SplitCalculationError.into());
    }

    Ok(SplitResult {
        company_amount,
        burn_amount,
        incentive_amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Task 2.1: z_total = 1_000_000 ──────────────────────────────────

    #[test]
    fn test_split_1_000_000() {
        let r = calculate_split(1_000_000).unwrap();
        assert_eq!(r.company_amount, 833_333, "company");
        assert_eq!(r.burn_amount, 83_333, "burn");
        assert_eq!(r.incentive_amount, 83_334, "incentive");
        assert_eq!(
            r.company_amount + r.burn_amount + r.incentive_amount,
            1_000_000,
            "sum"
        );
    }

    // ── Task 2.2: z_total = 1 (minimum edge case) ──────────────────────

    #[test]
    fn test_split_1() {
        let r = calculate_split(1).unwrap();
        assert_eq!(r.company_amount, 0, "company");
        assert_eq!(r.burn_amount, 0, "burn");
        assert_eq!(r.incentive_amount, 1, "incentive");
        assert_eq!(r.company_amount + r.burn_amount + r.incentive_amount, 1, "sum");
    }

    // ── Task 2.3: z_total = u64::MAX (overflow protection) ─────────────

    #[test]
    fn test_split_u64_max() {
        let r = calculate_split(u64::MAX).unwrap();
        assert_eq!(
            r.company_amount + r.burn_amount + r.incentive_amount,
            u64::MAX,
            "sum must equal u64::MAX"
        );
        // Verify no overflow happened — company ~83.3%, burn ~8.3%, incentive ~8.3%
        assert!(r.company_amount > r.burn_amount);
        assert!(r.company_amount > r.incentive_amount);
    }

    // ── Task 2.4: sum verification for known values ────────────────────

    #[test]
    fn test_split_sum_verification_known_values() {
        let test_cases: &[(u64, u64, u64, u64)] = &[
            (1_000_000, 833_333, 83_333, 83_334),
            (120, 100, 10, 10),
            (1, 0, 0, 1),
            (7, 5, 1, 1),
        ];

        for &(z_total, exp_company, exp_burn, exp_incentive) in test_cases {
            let r = calculate_split(z_total).unwrap();
            assert_eq!(r.company_amount, exp_company, "company for z_total={}", z_total);
            assert_eq!(r.burn_amount, exp_burn, "burn for z_total={}", z_total);
            assert_eq!(r.incentive_amount, exp_incentive, "incentive for z_total={}", z_total);
            assert_eq!(
                r.company_amount + r.burn_amount + r.incentive_amount,
                z_total,
                "sum for z_total={}",
                z_total
            );
        }
    }

    // ── Task 2.4 (extended): sum verification for many values ──────────

    #[test]
    fn test_split_sum_verification_range() {
        // Test 100+ values across the range
        for z_total in 1..=120 {
            let r = calculate_split(z_total).unwrap();
            assert_eq!(
                r.company_amount + r.burn_amount + r.incentive_amount,
                z_total,
                "sum failed for z_total={}",
                z_total
            );
        }

        // Large values
        for &z_total in &[
            1_000, 10_000, 100_000, 1_000_000, 10_000_000,
            100_000_000, 1_000_000_000, u64::MAX / 2, u64::MAX,
        ] {
            let r = calculate_split(z_total).unwrap();
            assert_eq!(
                r.company_amount + r.burn_amount + r.incentive_amount,
                z_total,
                "sum failed for z_total={}",
                z_total
            );
        }
    }

    // ── Task 2.5: z_total = 0 returns ZeroAmount error ─────────────────

    #[test]
    fn test_split_zero_returns_error() {
        let result = calculate_split(0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(ZupyTokenError::ZeroAmount as u32)
        );
    }

    // ── Additional: verify company > burn and company > incentive ──────

    #[test]
    fn test_split_proportions() {
        // For any z_total >= 6, company should be significantly larger
        for z_total in [6u64, 120, 1_000, 1_000_000, u64::MAX] {
            let r = calculate_split(z_total).unwrap();
            assert!(
                r.company_amount >= r.burn_amount,
                "company >= burn for z_total={}",
                z_total
            );
            assert!(
                r.company_amount >= r.incentive_amount,
                "company >= incentive for z_total={}",
                z_total
            );
        }
    }

    // ── Additional: incentive gets dust (ceiling) ──────────────────────

    #[test]
    fn test_incentive_gets_dust() {
        // When z_markup is odd, incentive should get the extra token
        let r = calculate_split(7).unwrap();
        // z_base = (7*100)/120 = 5, z_markup = 2, burn=1, incentive=1
        assert_eq!(r.burn_amount + r.incentive_amount, 2);
        assert!(r.incentive_amount >= r.burn_amount);
    }
}
