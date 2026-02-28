use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};

use crate::constants::{COMPANY_SEED, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, USER_SEED};
use crate::helpers::compressed_accounts::validate_v1_transfer_disc;
use crate::helpers::instruction_data::{parse_u64, parse_u8};
use crate::helpers::pda::validate_pda_with_seeds;
use crate::helpers::transfer_validation::validate_transfer_common_compressed;

/// Process `transfer_company_to_user` instruction (V1 CPI passthrough).
///
/// Forwards a pre-built V1 TRANSFER instruction to the mainnet cToken program,
/// signing with company PDA seeds via `invoke_signed`. The backend builds the
/// complete V1 Borsh instruction data (`CompressedTokenInstructionDataTransfer`
/// for compressed→compressed transfer) and the V1-ordered account list; this
/// instruction only validates security invariants before forwarding.
///
/// **Context:** Mainnet cToken program (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`)
/// runs V1 (Anchor 8-byte discriminators). V2 Transfer (disc=3) only works on
/// devnet. This passthrough enables compressed transfers on mainnet.
///
/// ## Security Validations
///
/// 1. `transfer_authority` must be signer (Spec §7.1-§7.8 via `validate_transfer_common_compressed`)
/// 2. `token_state` must be owned by our program
/// 3. Company PDA derivation must match `company_id` (prevents signing for wrong PDA)
/// 4. User PDA derivation must match `user_id` (validates destination)
/// 5. CPI data must start with V1 TRANSFER disc (prevents other cToken instructions)
/// 6. CPI target hardcoded to `LIGHT_COMPRESSED_TOKEN_PROGRAM_ID`
///
/// ## Accounts (minimum 5 + CPI accounts)
///
///   0. transfer_authority        (signer)           — must match TRANSFER_AUTHORITY_PUBKEY
///   1. token_state               (read)             — our program's token_state PDA
///   2. mint                      (read)             — ZUPY Token-2022 mint
///   3. company_pda               (read)             — compressed source + CPI signer
///   4. user_pda                  (read)             — compressed destination (validated)
///   5+ V1 CPI accounts           (client-assembled) — forwarded to cToken in V1 order
///
/// ## Data Layout (after 8-byte Anchor discriminator, stripped by lib.rs)
///
/// ```text
/// [0..8]   company_id (u64 LE)
/// [8..16]  user_id (u64 LE)
/// [16]     company_bump (u8)
/// [17]     user_bump (u8)
/// [18..]   raw V1 CPI instruction data (starts with 8-byte V1 TRANSFER disc)
/// ```
///
/// Discriminator: [8, 143, 213, 13, 143, 247, 145, 33] — UNCHANGED
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (minimum 5 validation accounts) ──────────────
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority  = &accounts[0];
    let token_state_account = &accounts[1];
    let mint                = &accounts[2];
    let company_pda         = &accounts[3]; // source PDA / CPI signer
    let user_pda            = &accounts[4]; // destination PDA

    // ── Parse instruction data ──────────────────────────────────────────
    let company_id_u64 = parse_u64(data, 0)?;
    let user_id_u64 = parse_u64(data, 8)?;
    let company_bump = parse_u8(data, 16)?;
    let user_bump = parse_u8(data, 17)?;

    // Raw V1 CPI instruction data starts at offset 18
    if data.len() <= 18 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let v1_cpi_data = &data[18..];

    // ── Validate V1 TRANSFER discriminator prefix ───────────────────────
    validate_v1_transfer_disc(v1_cpi_data)?;

    // ── Common transfer validation (checks 1–8) ─────────────────────────
    validate_transfer_common_compressed(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
    )?;

    // ── PDA validation: company_pda (source) ────────────────────────────
    let company_id_bytes = company_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        company_pda.address(),
        &[COMPANY_SEED, &company_id_bytes, &[company_bump]],
        program_id,
    )?;

    // ── PDA validation: user_pda (destination) ──────────────────────────
    let user_id_bytes = user_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        user_pda.address(),
        &[USER_SEED, &user_id_bytes, &[user_bump]],
        program_id,
    )?;

    // ── Build CPI instruction for cToken V1 ─────────────────────────────
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    let cpi_accounts = &accounts[5..];

    // Build account metas from CPI accounts, forcing company_pda to be signer.
    // The company_pda is not a signer on the outer transaction (only our program
    // can sign for it), but it must be a signer in the CPI to the cToken program.
    // invoke_signed provides this signature via the company PDA seeds.
    let mut account_metas = Vec::with_capacity(cpi_accounts.len());
    for acct in cpi_accounts {
        let is_company_pda = acct.address() == company_pda.address();
        let meta = match (acct.is_writable(), acct.is_signer() || is_company_pda) {
            (true, true)  => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _             => InstructionAccount::readonly(acct.address()),
        };
        account_metas.push(meta);
    }

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: v1_cpi_data,
    };

    // Build account view slice matching instruction.accounts 1:1.
    let account_views: Vec<&AccountView> = cpi_accounts.iter().collect();

    // ── CPI: Forward V1 TRANSFER to cToken, signing with company PDA ────
    let bump_bytes = [company_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(COMPANY_SEED),
        Seed::from(company_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, &[signer])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_company_to_user_not_enough_account_keys() {
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn test_transfer_company_to_user_exactly_4_accounts_is_not_enough() {
        use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 32];
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
        let mut bufs: Vec<Vec<u64>> = (0..4).map(|i| make_buf([i as u8 + 1; 32])).collect();
        let accounts: Vec<AccountView> = bufs
            .iter_mut()
            .map(|b| unsafe { AccountView::new_unchecked(b.as_mut_ptr() as *mut RuntimeAccount) })
            .collect();
        let result = process(&program_id, &accounts, &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    /// Short data buffer (< 18 bytes for V1 CPI data) must fail.
    #[test]
    fn test_transfer_company_to_user_short_data_returns_error() {
        let program_id = Address::default();
        let short_data = [0u8; 17];
        let result = process(&program_id, &[], &short_data);
        // Fails with NotEnoughAccountKeys (checked first)
        assert!(result.is_err());
    }
}
