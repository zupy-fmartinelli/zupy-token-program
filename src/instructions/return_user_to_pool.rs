use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, LIGHT_TOKEN_CPI_AUTHORITY, TOKEN_2022_PROGRAM_ID, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{
    cpi_decompress_to_spl, derive_spl_interface_pda,
};
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{validate_pda, validate_pda_with_seeds};
use crate::helpers::transfer_validation::validate_transfer_common;
use crate::state::token_state::TokenState;

/// Process `return_user_to_pool` instruction (Z$ reversal).
///
/// Decompresses user compressed balance back to the pool ATA via Light Protocol.
/// Path A reverse for User PDAs — mirrors return_to_pool but uses USER_SEED.
///
/// **Rate Limiting:** Not included on-chain by design. Reversals are admin-only
/// operations gated by `transfer_authority` signer check + backend management
/// command with `--delay` throttle. On-chain rate limiting may be added in a
/// future version if self-service reversals are introduced.
///
/// Accounts (11 minimum):
///   0. transfer_authority        (signer)           — must match TRANSFER_AUTHORITY_PUBKEY
///   1. token_state               (read)             — our program's token_state PDA
///   2. mint                      (read)             — ZUPY Token-2022 mint
///   3. user_pda                  (read)             — compressed source + CPI authority
///   4. pool_ata                  (writable)         — destination SPL ATA
///   5. fee_payer                 (writable, signer) — pays Light Protocol rent/fees
///   6. token_program             (read)             — Token-2022 program (spl_token_program for Light)
///   7. system_program            (read)             — System program
///   8. compressed_token_program  (read)             — Light cToken program
///   9. compressed_token_authority (read)            — Light cToken authority PDA
///   10. spl_interface_pda        (writable)         — Light SPL pool PDA (seeds=[b"pool", mint])
///   11+ Light system accounts                       — Merkle tree, nullifier queue, noop (client-injected)
///
/// Data: user_id_u64 (0-7) + amount (8-15) + user_bump (16) + memo (17+)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (11 accounts minimum) ─────────────────────────
    if accounts.len() < 11 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority    = &accounts[0];
    let token_state_account   = &accounts[1];
    let mint                  = &accounts[2];
    let user_pda              = &accounts[3];
    let pool_ata              = &accounts[4];
    let fee_payer             = &accounts[5];
    let token_program         = &accounts[6];
    let system_program        = &accounts[7];
    let compressed_token_prog = &accounts[8];
    let compressed_token_auth = &accounts[9];
    let spl_interface_pda     = &accounts[10];

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let amount = parse_u64(data, 8)?;
    let user_bump = parse_u8(data, 16)?;
    let (memo, _) = parse_string(data, 17)?;

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Common transfer validation (9 checks, Spec §7.1-§7.8) ───────────
    validate_transfer_common(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
        token_program,
    )?;

    // ── Additional signer check: fee_payer ──────────────────────────────
    if !fee_payer.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Verify compressed_token_program is the Light cToken program ──────
    let expected_ctoken: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    if compressed_token_prog.address() != &expected_ctoken {
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── Verify compressed_token_authority is the canonical cToken CPI PDA ─
    let expected_ctoken_auth = Address::from(LIGHT_TOKEN_CPI_AUTHORITY);
    if compressed_token_auth.address() != &expected_ctoken_auth {
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── PDA validation: user_pda (via client-provided bump) ──────────────
    let user_id_bytes = user_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        user_pda.address(),
        &[USER_SEED, &user_id_bytes, &[user_bump]],
        program_id,
    )?;

    // ── Pool ATA validation ─────────────────────────────────────────────
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });
    if pool_ata.address().as_ref() != state.pool_ata() {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }
    // Pool ATA must be owned by Token-2022 (Spec §7.1)
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !pool_ata.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }

    // ── Validate spl_interface_pda address and derive bump ───────────────
    let mint_key: [u8; 32] = mint.address().as_ref().try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let (expected_spl_pda, spl_bump) = derive_spl_interface_pda(&mint_key);
    validate_pda(spl_interface_pda.address(), &expected_spl_pda)?;

    // ── CPI: Decompress user compressed balance → pool ATA ────────────
    // user_pda signs with 3-seed pattern (USER_SEED + user_id + bump)
    let bump_bytes = [user_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_decompress_to_spl(
        compressed_token_prog,
        compressed_token_auth,
        fee_payer,
        mint,
        pool_ata,
        user_pda,
        spl_interface_pda,
        token_program,
        system_program,
        amount,
        spl_bump,
        &accounts[11..],
        &[signer],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify new account count check: at least 11 accounts required.
    /// Passing fewer than 11 accounts must return NotEnoughAccountKeys.
    #[test]
    fn test_return_user_to_pool_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }

    /// Short data buffer (< 17 bytes) must fail during parse.
    #[test]
    fn test_return_user_to_pool_short_data_returns_error() {
        let program_id = Address::default();
        // 8 bytes is too short — parse_u64 at offset 8 requires 16 bytes minimum
        let short_data = [0u8; 8];
        let result = process(&program_id, &[], &short_data);
        // Should fail with NotEnoughAccountKeys (checked first) or parse error
        assert!(result.is_err());
    }
}
