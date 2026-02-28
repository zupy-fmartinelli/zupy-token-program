use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::COMPANY_SEED;
use crate::helpers::return_to_pool_common::v1_passthrough_to_pool;

/// Process `return_to_pool_v1` instruction (V1 CPI passthrough, mainnet).
///
/// Forwards a pre-built V1 TRANSFER instruction to the mainnet cToken program,
/// signing with company PDA seeds via `invoke_signed`.
///
/// Delegates to [`v1_passthrough_to_pool`] with `COMPANY_SEED`.
/// See that function for full account layout, data format, and security validations.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    v1_passthrough_to_pool(program_id, accounts, data, COMPANY_SEED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::error::ProgramError;

    #[test]
    fn test_return_to_pool_v1_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }

    #[test]
    fn test_return_to_pool_v1_short_data_returns_error() {
        let program_id = Address::default();
        let short_data = [0u8; 8];
        let result = process(&program_id, &[], &short_data);
        assert!(result.is_err());
    }
}
