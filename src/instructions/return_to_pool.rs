use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::COMPANY_SEED;
use crate::helpers::return_to_pool_common::decompress_to_pool;

/// Process `return_to_pool` instruction (compressed version).
///
/// Decompresses company compressed balance back to the pool ATA via Light Protocol.
/// Path A reverse — no separate ValidityProof param needed (Light system accounts handle proof).
///
/// Delegates to [`decompress_to_pool`] with `COMPANY_SEED`.
/// See that function for full account layout, data format, and security validations.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    decompress_to_pool(program_id, accounts, data, COMPANY_SEED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::error::ProgramError;

    #[test]
    fn test_return_to_pool_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }
}
