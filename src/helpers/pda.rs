use pinocchio::Address;
use pinocchio::error::ProgramError;

use crate::constants::{
    COMPANY_SEED, COUPON_SEED, DISTRIBUTION_POOL_SEED, INCENTIVE_POOL_SEED,
    RATE_LIMIT_SEED, TOKEN_STATE_SEED, USER_PDA_SEED, USER_SEED, ZUPY_CARD_MINT_SEED,
    ZUPY_CARD_SEED,
};
use crate::error::ZupyTokenError;

// ── PDA Derivation Functions ────────────────────────────────────────────

/// Derive token_state PDA. Seeds: `[TOKEN_STATE_SEED]`
pub fn derive_token_state_pda(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[TOKEN_STATE_SEED], program_id)
}

/// Derive company PDA. Seeds: `[b"company", &company_id.to_le_bytes()]`
pub fn derive_company_pda(program_id: &Address, company_id: u64) -> (Address, u8) {
    let bytes = company_id.to_le_bytes();
    Address::find_program_address(&[COMPANY_SEED, &bytes], program_id)
}

/// Derive user PDA. Seeds: `[b"user", &user_id.to_le_bytes()]`
pub fn derive_user_pda(program_id: &Address, user_id: u64) -> (Address, u8) {
    let bytes = user_id.to_le_bytes();
    Address::find_program_address(&[USER_SEED, &bytes], program_id)
}

/// Derive incentive_pool PDA. Seeds: `[b"incentive_pool"]`
pub fn derive_incentive_pool_pda(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[INCENTIVE_POOL_SEED], program_id)
}

/// Derive distribution_pool PDA. Seeds: `[b"distribution_pool"]`
pub fn derive_distribution_pool_pda(program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[DISTRIBUTION_POOL_SEED], program_id)
}

/// Derive zupy_card PDA. Seeds: `[b"zupy_card", &user_ksuid]`
pub fn derive_zupy_card_pda(program_id: &Address, user_ksuid: &[u8]) -> (Address, u8) {
    Address::find_program_address(&[ZUPY_CARD_SEED, user_ksuid], program_id)
}

/// Derive zupy_card_mint PDA. Seeds: `[b"zupy_card_mint", &user_ksuid]`
pub fn derive_zupy_card_mint_pda(program_id: &Address, user_ksuid: &[u8]) -> (Address, u8) {
    Address::find_program_address(&[ZUPY_CARD_MINT_SEED, user_ksuid], program_id)
}

/// Derive coupon_mint PDA. Seeds: `[b"coupon", &coupon_ksuid]`
pub fn derive_coupon_mint_pda(program_id: &Address, coupon_ksuid: &[u8]) -> (Address, u8) {
    Address::find_program_address(&[COUPON_SEED, coupon_ksuid], program_id)
}

/// Derive user_nft PDA. Seeds: `[b"user_pda", &user_ksuid]`
pub fn derive_user_nft_pda(program_id: &Address, user_ksuid: &[u8]) -> (Address, u8) {
    Address::find_program_address(&[USER_PDA_SEED, user_ksuid], program_id)
}

/// Derive rate_limit PDA. Seeds: `[b"rate_limit", authority]`
pub fn derive_rate_limit_pda(program_id: &Address, authority: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[RATE_LIMIT_SEED, authority], program_id)
}

// ── Validation ──────────────────────────────────────────────────────────

/// Validate that an account key matches the expected PDA.
/// Returns `InvalidPDA` error if they don't match.
#[inline(always)]
pub fn validate_pda(account_key: &Address, expected_pda: &Address) -> Result<(), ProgramError> {
    if account_key != expected_pda {
        return Err(ZupyTokenError::InvalidPDA.into());
    }
    Ok(())
}

/// Validate a PDA using `create_program_address` with caller-provided seeds (including bump).
/// More efficient than `find_program_address` — saves ~15,000 CU per call.
///
/// # Usage
/// ```ignore
/// let id_bytes = id_u64.to_le_bytes();
/// validate_pda_with_seeds(
///     account.address(),
///     &[SEED, &id_bytes, &[bump]],
///     program_id,
/// )?;
/// ```
#[inline(always)]
pub fn validate_pda_with_seeds(
    account_key: &Address,
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<(), ProgramError> {
    let expected = Address::create_program_address(seeds, program_id)
        .map_err(|_| ZupyTokenError::InvalidPDA)?;
    if account_key != &expected {
        return Err(ZupyTokenError::InvalidPDA.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROGRAM_ID;

    fn test_program_id() -> Address {
        Address::from(PROGRAM_ID)
    }

    // ── AC7: PDA derivation consistency tests ───────────────────────────

    #[test]
    fn test_token_state_pda_deterministic() {
        let pid = test_program_id();
        let (addr1, bump1) = derive_token_state_pda(&pid);
        let (addr2, bump2) = derive_token_state_pda(&pid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_company_pda_deterministic() {
        let pid = test_program_id();
        let (addr1, bump1) = derive_company_pda(&pid, 42);
        let (addr2, bump2) = derive_company_pda(&pid, 42);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_company_pda_different_ids_produce_different_addresses() {
        let pid = test_program_id();
        let (addr1, _) = derive_company_pda(&pid, 1);
        let (addr2, _) = derive_company_pda(&pid, 2);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_user_pda_deterministic() {
        let pid = test_program_id();
        let (addr1, bump1) = derive_user_pda(&pid, 999);
        let (addr2, bump2) = derive_user_pda(&pid, 999);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_user_pda_different_ids_produce_different_addresses() {
        let pid = test_program_id();
        let (addr1, _) = derive_user_pda(&pid, 100);
        let (addr2, _) = derive_user_pda(&pid, 200);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_incentive_pool_pda_deterministic() {
        let pid = test_program_id();
        let (addr1, bump1) = derive_incentive_pool_pda(&pid);
        let (addr2, bump2) = derive_incentive_pool_pda(&pid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_distribution_pool_pda_deterministic() {
        let pid = test_program_id();
        let (addr1, bump1) = derive_distribution_pool_pda(&pid);
        let (addr2, bump2) = derive_distribution_pool_pda(&pid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_zupy_card_pda_deterministic() {
        let pid = test_program_id();
        let ksuid = b"0ujsszwN8NRY24YaXiTIE2VWDTS";
        let (addr1, bump1) = derive_zupy_card_pda(&pid, ksuid);
        let (addr2, bump2) = derive_zupy_card_pda(&pid, ksuid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_zupy_card_pda_different_ksuids_produce_different_addresses() {
        let pid = test_program_id();
        let (addr1, _) = derive_zupy_card_pda(&pid, b"0ujsszwN8NRY24YaXiTIE2VWDTS");
        let (addr2, _) = derive_zupy_card_pda(&pid, b"0ujsszwN8NRY24YaXiTIE2VWDTX");
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_zupy_card_mint_pda_deterministic() {
        let pid = test_program_id();
        let ksuid = b"0ujsszwN8NRY24YaXiTIE2VWDTS";
        let (addr1, bump1) = derive_zupy_card_mint_pda(&pid, ksuid);
        let (addr2, bump2) = derive_zupy_card_mint_pda(&pid, ksuid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_zupy_card_and_zupy_card_mint_are_different() {
        let pid = test_program_id();
        let ksuid = b"0ujsszwN8NRY24YaXiTIE2VWDTS";
        let (card_addr, _) = derive_zupy_card_pda(&pid, ksuid);
        let (mint_addr, _) = derive_zupy_card_mint_pda(&pid, ksuid);
        assert_ne!(card_addr, mint_addr);
    }

    #[test]
    fn test_coupon_mint_pda_deterministic() {
        let pid = test_program_id();
        let ksuid = b"1ujsszwN8NRY24YaXiTIE2VWDTS";
        let (addr1, bump1) = derive_coupon_mint_pda(&pid, ksuid);
        let (addr2, bump2) = derive_coupon_mint_pda(&pid, ksuid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_user_nft_pda_deterministic() {
        let pid = test_program_id();
        let ksuid = b"0ujsszwN8NRY24YaXiTIE2VWDTS";
        let (addr1, bump1) = derive_user_nft_pda(&pid, ksuid);
        let (addr2, bump2) = derive_user_nft_pda(&pid, ksuid);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_rate_limit_pda_deterministic() {
        let pid = test_program_id();
        let authority = [42u8; 32];
        let (addr1, bump1) = derive_rate_limit_pda(&pid, &authority);
        let (addr2, bump2) = derive_rate_limit_pda(&pid, &authority);
        assert_eq!(addr1, addr2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_rate_limit_pda_different_authorities_produce_different_addresses() {
        let pid = test_program_id();
        let (addr1, _) = derive_rate_limit_pda(&pid, &[1u8; 32]);
        let (addr2, _) = derive_rate_limit_pda(&pid, &[2u8; 32]);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_all_single_seed_pdas_are_distinct() {
        let pid = test_program_id();
        let (ts, _) = derive_token_state_pda(&pid);
        let (ip, _) = derive_incentive_pool_pda(&pid);
        let (dp, _) = derive_distribution_pool_pda(&pid);
        assert_ne!(ts, ip);
        assert_ne!(ts, dp);
        assert_ne!(ip, dp);
    }

    #[test]
    fn test_pda_bumps_are_valid() {
        let pid = test_program_id();
        let (pda, _bump) = derive_token_state_pda(&pid);
        // PDA should be off the ed25519 curve — verified by create_program_address succeeding
        let seeds_with_bump: &[&[u8]] = &[TOKEN_STATE_SEED, &[_bump]];
        let verified = Address::create_program_address(seeds_with_bump, &pid);
        assert!(verified.is_ok());
        assert_eq!(verified.unwrap(), pda);
    }

    // ── AC7: validate_pda tests ─────────────────────────────────────────

    #[test]
    fn test_validate_pda_matching() {
        let pid = test_program_id();
        let (pda, _) = derive_token_state_pda(&pid);
        assert!(validate_pda(&pda, &pda).is_ok());
    }

    #[test]
    fn test_validate_pda_mismatch_returns_error() {
        let pid = test_program_id();
        let (pda, _) = derive_token_state_pda(&pid);
        let wrong = Address::from([0u8; 32]);
        let result = validate_pda(&wrong, &pda);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(ZupyTokenError::InvalidPDA as u32)
        );
    }

    #[test]
    fn test_validate_pda_with_derived_pda() {
        let pid = test_program_id();
        let (expected, _) = derive_company_pda(&pid, 42);
        // Simulate passing the correct account key
        assert!(validate_pda(&expected, &expected).is_ok());
        // Simulate passing wrong account key
        let (wrong, _) = derive_company_pda(&pid, 43);
        assert!(validate_pda(&wrong, &expected).is_err());
    }

    // ── validate_pda_with_seeds tests ────────────────────────────────────

    #[test]
    fn test_validate_pda_with_seeds_happy_path() {
        let pid = test_program_id();
        let (expected, bump) = derive_company_pda(&pid, 42);
        let id_bytes = 42u64.to_le_bytes();
        assert!(validate_pda_with_seeds(
            &expected,
            &[COMPANY_SEED, &id_bytes, &[bump]],
            &pid,
        ).is_ok());
    }

    #[test]
    fn test_validate_pda_with_seeds_wrong_address() {
        let pid = test_program_id();
        let (_expected, bump) = derive_company_pda(&pid, 42);
        let wrong = Address::from([0xDD; 32]);
        let id_bytes = 42u64.to_le_bytes();
        let result = validate_pda_with_seeds(
            &wrong,
            &[COMPANY_SEED, &id_bytes, &[bump]],
            &pid,
        );
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(ZupyTokenError::InvalidPDA as u32)
        );
    }

    #[test]
    fn test_validate_pda_with_seeds_wrong_bump() {
        let pid = test_program_id();
        let (expected, bump) = derive_company_pda(&pid, 42);
        let id_bytes = 42u64.to_le_bytes();
        // Use a different bump — should fail (either InvalidPDA or create_program_address error)
        let wrong_bump = bump.wrapping_add(1);
        let result = validate_pda_with_seeds(
            &expected,
            &[COMPANY_SEED, &id_bytes, &[wrong_bump]],
            &pid,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_pda_with_seeds_single_seed() {
        let pid = test_program_id();
        let (expected, bump) = derive_token_state_pda(&pid);
        assert!(validate_pda_with_seeds(
            &expected,
            &[TOKEN_STATE_SEED, &[bump]],
            &pid,
        ).is_ok());
    }
}
