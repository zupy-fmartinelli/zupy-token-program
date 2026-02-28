use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::cpi_compressed_transfer;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::validate_pda_with_seeds;
use crate::helpers::transfer_validation::validate_transfer_common_compressed;

/// Process `transfer_user_to_company` instruction.
///
/// Transfers ZUPY from user compressed balance to company compressed balance via
/// Light cToken `Transfer` CPI (Path B: compressed → compressed). No ATA created.
///
/// Accounts (8):
///   0. transfer_authority (signer)
///   1. token_state (read)
///   2. mint (read)
///   3. user_pda (read)                 — source owner / PDA signer
///   4. company_pda (read)              — destination owner
///   5. fee_payer (writable, signer)    — pays Light state tree fees
///   6. system_program (read)
///   7. compressed_token_program (read) — cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
///
/// Data: user_id_u64 (u64) + company_id_u64 (u64) + amount (u64)
///       + user_bump (u8) + company_bump (u8) + memo (String)
///
/// Discriminator: [186, 233, 22, 40, 87, 223, 252, 131] — UNCHANGED
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (8 accounts minimum) ─────────────────────────
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let user_pda = &accounts[3];    // source owner / PDA signer
    let company_pda = &accounts[4]; // destination owner
    let fee_payer = &accounts[5];
    let system_program = &accounts[6];
    let compressed_token_program = &accounts[7];

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let company_id_u64 = parse_u64(data, 8)?;
    let amount = parse_u64(data, 16)?;
    let user_bump = parse_u8(data, 24)?;
    let company_bump = parse_u8(data, 25)?;
    let (memo, _) = parse_string(data, 26)?;
    // Remaining bytes (if any): ValidityProof + InputTokenDataWithContext from Photon
    // — accepted in instruction data per AC3, not consumed by on-chain program.

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Common transfer validation (checks 1–8) ─────────────────────────
    validate_transfer_common_compressed(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
    )?;

    // ── Check 9: compressed_token_program is Light cToken program ───────
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

    // ── PDA validation: company_pda (destination) ───────────────────────
    let company_id_bytes = company_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        company_pda.address(),
        &[COMPANY_SEED, &company_id_bytes, &[company_bump]],
        program_id,
    )?;

    // ── CPI: compressed transfer (user_pda signs) ───────────────────────
    let user_bump_bytes = [user_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_compressed_transfer(
        compressed_token_program,
        fee_payer,
        user_pda,    // source
        company_pda, // destination
        user_pda,    // authority (source PDA signs)
        system_program,
        amount,
        &[signer],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_user_to_company_not_enough_account_keys() {
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 26];
        let result = process(&program_id, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn test_transfer_user_to_company_exactly_7_accounts_is_not_enough() {
        use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 26];
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
        let mut bufs: Vec<Vec<u64>> = (0..7).map(|i| make_buf([i as u8 + 1; 32])).collect();
        let accounts: Vec<AccountView> = bufs
            .iter_mut()
            .map(|b| unsafe { AccountView::new_unchecked(b.as_mut_ptr() as *mut RuntimeAccount) })
            .collect();
        let result = process(&program_id, &accounts, &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }
}
