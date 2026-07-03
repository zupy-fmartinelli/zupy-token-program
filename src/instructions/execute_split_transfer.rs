use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, INCENTIVE_POOL_SEED, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::cpi_compressed_transfer;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::pda::{validate_light_ctoken_program, validate_id_pda, validate_pda_with_seeds};
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::instructions::split_math::checked_total;

/// Process `execute_split_transfer` instruction.
///
/// **Burn-free explicit-amount split (AD-A1 / AD-A2).** The split is computed
/// OFF-CHAIN in the ledger; this program executes the amounts it is handed and
/// invents nothing. There is **no burn** — money is conserved, only moved:
///   User (compressed) → Company (`company_amount`) + Incentive Pool (`pool_amount`)
/// Two Light cToken Transfer CPIs, both signed by user_pda. The Pool leg is
/// skipped when `pool_amount == 0` (taxa_pool = 0 — high-volume merchant).
///
/// Accounts (9+):
///   0. transfer_authority (signer)
///   1. token_state (read)
///   2. mint (read)                      — validated; no longer burned
///   3. user_pda (read)                  — source / PDA signer for both CPIs
///   4. company_pda (read)               — destination for Transfer 1 (company_amount)
///   5. incentive_pool_pda (read)        — destination for Transfer 2 (pool_amount)
///   6. fee_payer (writable, signer)     — pays Light state tree fees
///   7. system_program (read)
///   8. compressed_token_program (read)  — cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
///   9+. Light system accounts (merkle tree, nullifier queue, noop — passed by client)
///
/// Data: user_id_u64 (u64) + company_id_u64 (u64)
///       + company_amount (u64) + pool_amount (u64)
///       + user_bump (u8) + company_bump (u8) + incentive_bump (u8)
///       + operation_type (String)
///
/// Discriminator: [51, 254, 61, 214, 234, 138, 101, 214] — UNCHANGED (AC6).
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
    let user_pda = &accounts[3];           // source / PDA signer for both CPIs
    let company_pda = &accounts[4];        // destination for Transfer 1
    let incentive_pool_pda = &accounts[5]; // destination for Transfer 2
    let fee_payer = &accounts[6];
    let system_program = &accounts[7];
    let compressed_token_program = &accounts[8];
    // accounts[9..] = Light system accounts (merkle tree, nullifier queue, etc.)

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let company_id_u64 = parse_u64(data, 8)?;
    let company_amount = parse_u64(data, 16)?;
    let pool_amount = parse_u64(data, 24)?;
    let user_bump = parse_u8(data, 32)?;
    let company_bump = parse_u8(data, 33)?;
    let incentive_bump = parse_u8(data, 34)?;
    let (operation_type, _) = parse_string(data, 35)?;

    // ── Input validation ────────────────────────────────────────────────
    // Explicit amounts must conserve to a positive total (no burn, no minting).
    // Overflow-guarded; company_amount must be positive (the base always is).
    let _total = checked_total(company_amount, pool_amount)?;
    if company_amount == 0 {
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
    validate_light_ctoken_program(compressed_token_program)?;

    // ── PDA validation: user (source), company + incentive pool (dests) ──
    let user_id_bytes = user_id_u64.to_le_bytes();
    validate_id_pda(user_pda.address(), USER_SEED, user_id_u64, user_bump, program_id)?;
    validate_id_pda(company_pda.address(), COMPANY_SEED, company_id_u64, company_bump, program_id)?;
    validate_pda_with_seeds(
        incentive_pool_pda.address(),
        &[INCENTIVE_POOL_SEED, &[incentive_bump]],
        program_id,
    )?;

    // ── CPI signer seeds: user_pda signs both CPIs ───────────────────────
    let user_bump_bytes = [user_bump];

    // ── CPI 1: Compressed Transfer User → Company (company_amount) ────────
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
        company_amount,
        &[signer1],
    )?;

    // ── CPI 2: Compressed Transfer User → Incentive Pool (pool_amount) ───
    // Skipped when pool_amount == 0 (taxa_pool = 0 → no Pool cut, AD-A2).
    if pool_amount > 0 {
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
            pool_amount,
            &[signer2],
        )?;
    }

    // No burn leg (AD-A2): money is conserved, never destroyed on-chain.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NotEnoughAccountKeys unit tests (account check precedes parse) ────

    #[test]
    fn test_execute_split_transfer_not_enough_account_keys_zero() {
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 35];
        let result = process(&program_id, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn test_execute_split_transfer_exactly_8_accounts_is_not_enough() {
        use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 35];
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
