use pinocchio::error::ProgramError;

use crate::error::ZupyTokenError;

/// Total-of-legs guard for `execute_split_transfer` (burn-free model, AD-A1).
///
/// The z_direct split is now computed OFF-CHAIN in the ledger: the program
/// receives EXPLICIT `company_amount` + `pool_amount` and executes exactly
/// those two transfers with **no burn**. No split ratio (the old 83.3/8.3/8.3)
/// lives on-chain anymore — the program only conserves what it is handed.
///
/// This helper keeps the Audit 12.1 safety net: it sums the two legs with
/// `checked_add` (overflow → error) and rejects a zero total. It performs no
/// division and invents no amounts.
pub fn checked_total(company_amount: u64, pool_amount: u64) -> Result<u64, ProgramError> {
    let total = company_amount
        .checked_add(pool_amount)
        .ok_or(ZupyTokenError::SplitCalculationError)?;

    if total == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checked_total_basic() {
        // taxa = 0.20 → base 1000, pool 200
        assert_eq!(checked_total(1_000, 200).unwrap(), 1_200);
    }

    #[test]
    fn test_checked_total_zero_pool_is_valid() {
        // taxa = 0 → no pool leg, still a valid redemption
        assert_eq!(checked_total(1_000, 0).unwrap(), 1_000);
    }

    #[test]
    fn test_checked_total_zero_total_rejected() {
        assert_eq!(
            checked_total(0, 0).unwrap_err(),
            ProgramError::Custom(ZupyTokenError::ZeroAmount as u32)
        );
    }

    #[test]
    fn test_checked_total_overflow_rejected() {
        assert_eq!(
            checked_total(u64::MAX, 1).unwrap_err(),
            ProgramError::Custom(ZupyTokenError::SplitCalculationError as u32)
        );
    }

    #[test]
    fn test_checked_total_max_no_overflow() {
        assert_eq!(checked_total(u64::MAX, 0).unwrap(), u64::MAX);
    }
}
