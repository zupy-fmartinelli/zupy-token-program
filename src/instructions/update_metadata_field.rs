use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::TOKEN_STATE_SEED;
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_update_metadata_field;
use crate::helpers::instruction_data::{parse_string, parse_u8};
use crate::helpers::transfer_validation::validate_metadata_accounts;

/// Validate metadata field value by type (0=Name, 1=Symbol, 2=Uri).
#[inline(always)]
fn validate_metadata_field(field: u8, value: &str) -> Result<(), pinocchio::error::ProgramError> {
    match field {
        0 if value.is_empty() || value.len() > 32 => Err(ZupyTokenError::InvalidMetadataName.into()),
        1 if value.is_empty() || value.len() > 10 => Err(ZupyTokenError::InvalidMetadataSymbol.into()),
        2 if value.is_empty() || value.len() > 200 => Err(ZupyTokenError::InvalidMetadataUri.into()),
        0..=2 => Ok(()),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Process `update_metadata_field` instruction.
///
/// Updates a metadata field via spl-token-metadata-interface UpdateField CPI.
/// token_state PDA signs via invoke_signed.
///
/// Accounts (4):
///   0. authority (writable, signer) — must be token_state.treasury()
///   1. token_state (read) — PDA [TOKEN_STATE_SEED]
///   2. mint (writable) — Token-2022 mint with MetadataPointer
///   3. token_program (read) — Token-2022
///
/// Data: field (u8: 0=Name, 1=Symbol, 2=Uri) + value (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (4 accounts) ─────────────────────────────────
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let token_program = &accounts[3];

    // ── Parse instruction data ──────────────────────────────────────────
    let field = parse_u8(data, 0)?;
    let (value, _) = parse_string(data, 1)?;

    // ── Field-specific validation ───────────────────────────────────────
    validate_metadata_field(field, value)?;

    // ── Metadata account validation (treasury + mint + token_program) ────
    let bump = validate_metadata_accounts(
        program_id, authority, token_state_account, mint, token_program,
    )?;

    // ── CPI: Update metadata field (token_state PDA signs) ──────────────
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 2] = [
        Seed::from(TOKEN_STATE_SEED),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_update_metadata_field(
        mint,
        token_state_account,
        token_program,
        field,
        value,
        &[signer],
    )?;

    Ok(())
}
