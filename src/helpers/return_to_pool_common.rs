//! Shared logic for return-to-pool instructions.
//!
//! Two variants parametrized by PDA seed (`COMPANY_SEED` or `USER_SEED`):
//!
//! - [`decompress_to_pool`]: V2 path — decompresses via Light Transfer2 (`cpi_decompress_to_spl`).
//!   Used by `return_to_pool` (company) and `return_user_to_pool` (user).
//!
//! - [`v1_passthrough_to_pool`]: V1 path — forwards pre-built V1 TRANSFER CPI to mainnet cToken.
//!   Used by `return_to_pool_v1` (company) and `return_user_to_pool_v1` (user).

use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{
    LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, LIGHT_TOKEN_CPI_AUTHORITY, TOKEN_2022_PROGRAM_ID,
};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{
    cpi_decompress_to_spl, derive_spl_interface_pda, validate_v1_transfer_disc,
};
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{validate_pda, validate_pda_with_seeds};
use crate::helpers::transfer_validation::validate_transfer_common;
use crate::state::token_state::TokenState;

/// V2 decompress path: compressed PDA balance → pool ATA via Light Transfer2.
///
/// Accounts (11 minimum):
///   0. transfer_authority        (signer)
///   1. token_state               (read)
///   2. mint                      (read)
///   3. entity_pda                (read)           — company or user PDA
///   4. pool_ata                  (writable)
///   5. fee_payer                 (writable, signer)
///   6. token_program             (read)
///   7. system_program            (read)
///   8. compressed_token_program  (read)
///   9. compressed_token_authority (read)
///   10. spl_interface_pda        (writable)
///   11+ Light system accounts
///
/// Data: entity_id (0-7) + amount (8-15) + entity_bump (16) + memo (17+)
pub fn decompress_to_pool(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
    pda_seed: &[u8],
) -> ProgramResult {
    // ── Account extraction (11 accounts minimum) ─────────────────────────
    if accounts.len() < 11 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let entity_pda = &accounts[3];
    let pool_ata = &accounts[4];
    let fee_payer = &accounts[5];
    let token_program = &accounts[6];
    let system_program = &accounts[7];
    let compressed_token_prog = &accounts[8];
    let compressed_token_auth = &accounts[9];
    let spl_interface_pda = &accounts[10];

    // ── Parse instruction data ──────────────────────────────────────────
    let entity_id_u64 = parse_u64(data, 0)?;
    let amount = parse_u64(data, 8)?;
    let entity_bump = parse_u8(data, 16)?;
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

    // ── PDA validation (via client-provided bump) ─────────────────────────
    let entity_id_bytes = entity_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        entity_pda.address(),
        &[pda_seed, &entity_id_bytes, &[entity_bump]],
        program_id,
    )?;

    // ── Pool ATA validation ─────────────────────────────────────────────
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });
    if pool_ata.address().as_ref() != state.pool_ata() {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !pool_ata.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }

    // ── Validate spl_interface_pda address and derive bump ───────────────
    let mint_key: [u8; 32] = mint
        .address()
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let (expected_spl_pda, spl_bump) = derive_spl_interface_pda(&mint_key);
    validate_pda(spl_interface_pda.address(), &expected_spl_pda)?;

    // ── CPI: Decompress entity compressed balance → pool ATA ────────────
    let bump_bytes = [entity_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(pda_seed),
        Seed::from(entity_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_decompress_to_spl(
        compressed_token_prog,
        compressed_token_auth,
        fee_payer,
        mint,
        pool_ata,
        entity_pda,
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

/// V1 CPI passthrough: forwards pre-built V1 TRANSFER to mainnet cToken program.
///
/// Accounts (minimum 6 + CPI accounts):
///   0. transfer_authority        (signer)
///   1. token_state               (read)
///   2. mint                      (read)
///   3. entity_pda                (read)           — company or user PDA
///   4. pool_ata                  (read)
///   5. token_program             (read)
///   6+ V1 CPI accounts           (client-assembled)
///
/// Data: entity_id (0-7) + entity_bump (8) + raw V1 CPI data (9+)
pub fn v1_passthrough_to_pool(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
    pda_seed: &[u8],
) -> ProgramResult {
    // ── Account extraction (minimum 6 validation accounts) ─────────────────
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let entity_pda = &accounts[3];
    let pool_ata = &accounts[4];
    let token_program = &accounts[5];

    // ── Parse instruction data ────────────────────────────────────────────
    let entity_id_u64 = parse_u64(data, 0)?;
    let entity_bump = parse_u8(data, 8)?;

    // Raw V1 CPI instruction data starts at offset 9
    if data.len() <= 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let v1_cpi_data = &data[9..];

    // ── Validate V1 TRANSFER discriminator prefix ──────────────────────────
    validate_v1_transfer_disc(v1_cpi_data)?;

    // ── Common transfer validation (9 checks, Spec §7.1-§7.8) ─────────────
    validate_transfer_common(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
        token_program,
    )?;

    // ── PDA validation (via client-provided bump) ────────────────────────
    let entity_id_bytes = entity_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        entity_pda.address(),
        &[pda_seed, &entity_id_bytes, &[entity_bump]],
        program_id,
    )?;

    // ── Pool ATA validation ───────────────────────────────────────────────
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });
    if pool_ata.address().as_ref() != state.pool_ata() {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !pool_ata.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }

    // ── Build CPI instruction for cToken V1 ───────────────────────────────
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    let cpi_accounts = &accounts[6..];

    // Build account metas, forcing entity_pda to be signer for invoke_signed.
    let mut account_metas = Vec::with_capacity(cpi_accounts.len());
    for acct in cpi_accounts {
        let is_entity_pda = acct.address() == entity_pda.address();
        let meta = match (acct.is_writable(), acct.is_signer() || is_entity_pda) {
            (true, true) => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _ => InstructionAccount::readonly(acct.address()),
        };
        account_metas.push(meta);
    }

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: v1_cpi_data,
    };

    let account_views: Vec<&AccountView> = cpi_accounts.iter().collect();

    // ── CPI: Forward V1 TRANSFER to cToken, signing with entity PDA ──────
    let bump_bytes = [entity_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(pda_seed),
        Seed::from(entity_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, &[signer])?;

    Ok(())
}
