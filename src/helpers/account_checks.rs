use pinocchio::AccountView;
use pinocchio::Address;
use pinocchio::error::ProgramError;

use crate::error::ZupyTokenError;

/// Assert that the account is a signer.
#[inline(always)]
pub fn assert_signer(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    Ok(())
}

/// Assert that the account is owned by the expected program.
#[inline(always)]
pub fn assert_owner(account: &AccountView, expected_owner: &Address) -> Result<(), ProgramError> {
    if !account.owned_by(expected_owner) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    Ok(())
}

/// Assert that the account's address matches the expected key.
#[inline(always)]
pub fn assert_key_eq(account: &AccountView, expected_key: &Address) -> Result<(), ProgramError> {
    if account.address() != expected_key {
        return Err(ZupyTokenError::InvalidPDA.into());
    }
    Ok(())
}

/// Assert that the account is owned by the given program ID.
/// Semantic alias for assert_owner with program-centric naming.
pub fn assert_program_id(account: &AccountView, program_id: &Address) -> Result<(), ProgramError> {
    assert_owner(account, program_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
    use core::mem::size_of;

    /// Helper: build a RuntimeAccount + trailing data in a properly-aligned buffer.
    /// Returns the buffer (must outlive any AccountView created from it).
    fn make_account_buf(
        address: [u8; 32],
        owner: [u8; 32],
        is_signer: bool,
    ) -> Vec<u64> {
        // Allocate u64-aligned memory for RuntimeAccount + 8 bytes trailing data
        let words = size_of::<RuntimeAccount>() / size_of::<u64>() + 1;
        let mut buf = vec![0u64; words];
        buf[0] = NOT_BORROWED as u64;

        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = is_signer as u8;
            (*raw).is_writable = 1;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = Address::from(address);
            (*raw).owner = Address::from(owner);
            (*raw).lamports = 0;
            (*raw).data_len = 8;
        }
        buf
    }

    fn view_from_buf(buf: &mut Vec<u64>) -> AccountView {
        unsafe { AccountView::new_unchecked(buf.as_mut_ptr() as *mut RuntimeAccount) }
    }

    // ── assert_signer tests ─────────────────────────────────────────────

    #[test]
    fn test_assert_signer_ok() {
        let mut buf = make_account_buf([1u8; 32], [0u8; 32], true);
        let account = view_from_buf(&mut buf);
        assert!(assert_signer(&account).is_ok());
    }

    #[test]
    fn test_assert_signer_fails_when_not_signer() {
        let mut buf = make_account_buf([1u8; 32], [0u8; 32], false);
        let account = view_from_buf(&mut buf);
        let result = assert_signer(&account);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    // ── assert_owner tests ──────────────────────────────────────────────

    #[test]
    fn test_assert_owner_ok() {
        let expected_owner = [42u8; 32];
        let mut buf = make_account_buf([1u8; 32], expected_owner, false);
        let account = view_from_buf(&mut buf);
        let owner_addr = Address::from(expected_owner);
        assert!(assert_owner(&account, &owner_addr).is_ok());
    }

    #[test]
    fn test_assert_owner_fails_when_wrong_owner() {
        let mut buf = make_account_buf([1u8; 32], [42u8; 32], false);
        let account = view_from_buf(&mut buf);
        let wrong_owner = Address::from([99u8; 32]);
        let result = assert_owner(&account, &wrong_owner);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    // ── assert_key_eq tests ─────────────────────────────────────────────

    #[test]
    fn test_assert_key_eq_ok() {
        let addr = [55u8; 32];
        let mut buf = make_account_buf(addr, [0u8; 32], false);
        let account = view_from_buf(&mut buf);
        let expected = Address::from(addr);
        assert!(assert_key_eq(&account, &expected).is_ok());
    }

    #[test]
    fn test_assert_key_eq_fails_when_mismatch() {
        let mut buf = make_account_buf([55u8; 32], [0u8; 32], false);
        let account = view_from_buf(&mut buf);
        let wrong_key = Address::from([99u8; 32]);
        let result = assert_key_eq(&account, &wrong_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidPDA as u32));
    }

    // ── assert_program_id tests ─────────────────────────────────────────

    #[test]
    fn test_assert_program_id_ok() {
        let program_id = [77u8; 32];
        let mut buf = make_account_buf([1u8; 32], program_id, false);
        let account = view_from_buf(&mut buf);
        let pid = Address::from(program_id);
        assert!(assert_program_id(&account, &pid).is_ok());
    }

    #[test]
    fn test_assert_program_id_delegates_to_assert_owner() {
        // Explicitly test the delegation path to ensure coverage
        let program_id = [77u8; 32];
        let mut buf = make_account_buf([1u8; 32], program_id, false);
        let account = view_from_buf(&mut buf);
        let pid = Address::from(program_id);
        // This calls assert_owner internally
        let result = assert_program_id(&account, &pid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_program_id_fails_when_wrong_program() {
        let mut buf = make_account_buf([1u8; 32], [77u8; 32], false);
        let account = view_from_buf(&mut buf);
        let wrong_pid = Address::from([88u8; 32]);
        let result = assert_program_id(&account, &wrong_pid);
        assert!(result.is_err());
    }
}
