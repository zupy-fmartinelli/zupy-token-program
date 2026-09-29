use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{validate_light_ctoken_program, validate_id_pda};
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::helpers::v1_transfer::{
    invoke_v1_transfer_signed, validate_v1_authority, validate_v1_transfer_payload, V1Leg,
};

/// Index of the first V1 cToken CPI account (`fee_payer`, then `authority`, …).
pub const U2C_V1_CPI_ACCOUNTS_START: usize = 8;

/// Process `transfer_user_to_company` instruction.
///
/// Moves Z$ from the user's compressed leaves to the company PDA (client →
/// store, used by "Pérolas + Z$" and settlement of "Só Z$").
///
/// ## 2026-09-29 (story 3.21) — why this changed, MEASURED
///
/// Up to `396df04` this instruction called `cpi_compressed_transfer` (cToken
/// disc=3, no proof). Unsigned mainnet simulation (3.17 code review, user
/// `2140389439281718293` → company `9068097475314820308`) fails with
/// `Custom(18063) InvalidTokenOwner` — disc=3 moves cToken *Solana accounts*,
/// not compressed leaves. It now forwards a V1 TRANSFER with validity proof
/// (the working `transfer_company_to_user` mechanism), signed by the user PDA,
/// after checking the payload moves exactly `amount` to the company plus an
/// optional change back to the user.
///
/// Accounts (10+):
/// ```text
///   0. transfer_authority (signer)
///   1. token_state (read)
///   2. mint (read)
///   3. user_pda (read)                 — owner of the input leaves / PDA signer
///   4. company_pda (read)              — owner of output 0
///   5. fee_payer (writable, signer)    — kept for layout compatibility
///   6. system_program (read)           — kept for layout compatibility
///   7. compressed_token_program (read) — cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
///   8+. V1 cToken CPI accounts (same order as `transfer_company_to_user` [5..],
///       with authority = user_pda)
/// ```
///
/// Data: user_id u64 + company_id u64 + amount u64 + user_bump u8 + company_bump u8
///       + memo (String) + V1 TRANSFER cToken data (disc + Vec<u8> Borsh).
/// A caller that stops after the memo (the `396df04` adapter) now fails with
/// `InvalidInstructionData` BEFORE any CPI.
///
/// Discriminator: [186, 233, 22, 40, 87, 223, 252, 131] — UNCHANGED
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (8 accounts minimum before the V1 CPI tail) ──
    if accounts.len() < U2C_V1_CPI_ACCOUNTS_START {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let user_pda = &accounts[3];    // owner of the input leaves / PDA signer
    let company_pda = &accounts[4]; // output 0
    let compressed_token_program = &accounts[7];
    let cpi_accounts = &accounts[U2C_V1_CPI_ACCOUNTS_START..];

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let company_id_u64 = parse_u64(data, 8)?;
    let amount = parse_u64(data, 16)?;
    let user_bump = parse_u8(data, 24)?;
    let company_bump = parse_u8(data, 25)?;
    let (memo, v1_offset) = parse_string(data, 26)?;
    let v1_data = &data[v1_offset..];

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
    validate_light_ctoken_program(compressed_token_program)?;

    // ── PDA validation: user (source), company (destination) ────────────
    let user_id_bytes = user_id_u64.to_le_bytes();
    validate_id_pda(user_pda.address(), USER_SEED, user_id_u64, user_bump, program_id)?;
    validate_id_pda(company_pda.address(), COMPANY_SEED, company_id_u64, company_bump, program_id)?;

    // ── The V1 payload must move exactly `amount` to the company ────────
    let legs = [V1Leg { owner: company_pda.address(), amount }];
    validate_v1_transfer_payload(v1_data, mint.address(), user_pda.address(), &legs)?;
    validate_v1_authority(cpi_accounts, user_pda)?;

    // ── CPI: V1 TRANSFER user → company (+ change), user PDA signs ──────
    let user_bump_bytes = [user_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    invoke_v1_transfer_signed(cpi_accounts, user_pda, v1_data, &[Signer::from(&signer_seeds)])
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
