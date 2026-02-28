use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, INCENTIVE_POOL_SEED, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{cpi_compressed_burn, cpi_compressed_transfer};
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::pda::validate_pda_with_seeds;
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::instructions::split_math::calculate_split;

/// Process `execute_split_transfer` instruction.
///
/// 20% markup split on compressed balances:
///   User (compressed) → Company (83.3%) + Incentive Pool (8.3%) + Burn (8.3%)
/// Three Light cToken CPIs: 2× Transfer + 1× Burn, all signed by user_pda.
///
/// Accounts (9+):
///   0. transfer_authority (signer)
///   1. token_state (read)
///   2. mint (writable)              — writable: BurnCpi decrements on-chain supply
///   3. user_pda (read)                  — source / PDA signer for all 3 CPIs
///   4. company_pda (read)               — destination for Transfer 1 (83.3%)
///   5. incentive_pool_pda (read)        — destination for Transfer 2 (8.3%)
///   6. fee_payer (writable, signer)     — pays Light state tree fees
///   7. system_program (read)
///   8. compressed_token_program (read)  — cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
///   9+. Light system accounts (merkle tree, nullifier queue, noop — passed by client)
///
/// Data: user_id_u64 (u64) + company_id_u64 (u64) + z_total (u64)
///       + user_bump (u8) + company_bump (u8) + incentive_bump (u8)
///       + operation_type (String)
///
/// Discriminator: [51, 254, 61, 214, 234, 138, 101, 214] — UNCHANGED (AC6)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (9 accounts minimum) ──────────────────────────
    if accounts.len() < 9 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let user_pda = &accounts[3];           // source / PDA signer for all 3 CPIs
    let company_pda = &accounts[4];        // destination for Transfer 1
    let incentive_pool_pda = &accounts[5]; // destination for Transfer 2
    let fee_payer = &accounts[6];
    let system_program = &accounts[7];
    let compressed_token_program = &accounts[8];
    // accounts[9..] = Light system accounts (merkle tree, nullifier queue, etc.)

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let company_id_u64 = parse_u64(data, 8)?;
    let z_total = parse_u64(data, 16)?;
    let user_bump = parse_u8(data, 24)?;
    let company_bump = parse_u8(data, 25)?;
    let incentive_bump = parse_u8(data, 26)?;
    let (operation_type, _) = parse_string(data, 27)?;

    // ── Input validation ────────────────────────────────────────────────
    if z_total == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    if operation_type != "mixed_payment" && operation_type != "z_direct" {
        return Err(ZupyTokenError::InvalidOperationType.into());
    }

    // ── Common transfer validation (compressed variant: checks 1–8) ──────
    validate_transfer_common_compressed(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
    )?;

    // ── Check 9: compressed_token_program is Light cToken program ────────
    let light_ctoken_addr = Address::from(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    if compressed_token_program.address() != &light_ctoken_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── PDA validation: user_pda (source) ───────────────────────────────
    let user_id_bytes = user_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        user_pda.address(),
        &[USER_SEED, &user_id_bytes, &[user_bump]],
        program_id,
    )?;

    // ── PDA validation: company_pda (destination 1) ─────────────────────
    let company_id_bytes = company_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        company_pda.address(),
        &[COMPANY_SEED, &company_id_bytes, &[company_bump]],
        program_id,
    )?;

    // ── PDA validation: incentive_pool_pda (destination 2) ──────────────
    validate_pda_with_seeds(
        incentive_pool_pda.address(),
        &[INCENTIVE_POOL_SEED, &[incentive_bump]],
        program_id,
    )?;

    // ── Split calculation (AC1–3, AC4 reused unchanged) ─────────────────
    let split = calculate_split(z_total)?;

    // ── CPI signer seeds: user_pda signs all 3 CPIs ──────────────────────
    let user_bump_bytes = [user_bump];

    // ── CPI 1: Compressed Transfer User → Company (company_amount, 83.3%) ─
    let signer_seeds1: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    let signer1 = Signer::from(&signer_seeds1);

    cpi_compressed_transfer(
        compressed_token_program,
        fee_payer,
        user_pda,    // source
        company_pda, // destination
        user_pda,    // authority (source PDA signs)
        system_program,
        split.company_amount,
        &[signer1],
    )?;

    // ── CPI 2: Compressed Transfer User → Incentive Pool (8.3%) ──────────
    // Re-create signer (consumed by previous CPI)
    let signer_seeds2: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    let signer2 = Signer::from(&signer_seeds2);

    cpi_compressed_transfer(
        compressed_token_program,
        fee_payer,
        user_pda,            // source
        incentive_pool_pda,  // destination
        user_pda,            // authority (source PDA signs)
        system_program,
        split.incentive_amount,
        &[signer2],
    )?;

    // ── CPI 3: Compressed Burn from User (burn_amount, 8.3%) ─────────────
    let signer_seeds3: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    let signer3 = Signer::from(&signer_seeds3);

    cpi_compressed_burn(
        compressed_token_program,
        fee_payer,
        user_pda, // authority (source PDA signs)
        mint,
        system_program,
        split.burn_amount,
        &accounts[9..],
        &[signer3],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Task 3.2: NotEnoughAccountKeys unit test ──────────────────────────

    #[test]
    fn test_execute_split_transfer_not_enough_account_keys_zero() {
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 27];
        let result = process(&program_id, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn test_execute_split_transfer_exactly_8_accounts_is_not_enough() {
        use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 27];
        fn make_buf(addr: [u8; 32]) -> Vec<u64> {
            let words = (core::mem::size_of::<RuntimeAccount>() + 7) / 8 + 1;
            let mut buf = vec![0u64; words];
            let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
            unsafe {
                (*raw).borrow_state = NOT_BORROWED;
                (*raw).address = Address::from(addr);
            }
            buf
        }
        let mut bufs: Vec<Vec<u64>> = (0..8).map(|i| make_buf([i as u8 + 1; 32])).collect();
        let accounts: Vec<AccountView> = bufs
            .iter_mut()
            .map(|b| unsafe { AccountView::new_unchecked(b.as_mut_ptr() as *mut RuntimeAccount) })
            .collect();
        let result = process(&program_id, &accounts, &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }
}
