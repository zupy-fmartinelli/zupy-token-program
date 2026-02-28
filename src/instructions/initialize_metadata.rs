use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::TOKEN_STATE_SEED;
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_initialize_metadata;
use crate::helpers::instruction_data::parse_string;
use crate::helpers::transfer_validation::validate_metadata_accounts;

/// Process `initialize_metadata` instruction.
///
/// Initializes Token-2022 metadata via spl-token-metadata-interface CPI.
/// token_state PDA signs via invoke_signed.
///
/// Accounts (4):
///   0. authority (writable, signer) — must be token_state.treasury()
///   1. token_state (read) — PDA [TOKEN_STATE_SEED]
///   2. mint (writable) — Token-2022 mint with MetadataPointer
///   3. token_program (read) — Token-2022
///
/// Data: name (String) + symbol (String) + uri (String)
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
    let (name, offset) = parse_string(data, 0)?;
    let (symbol, offset) = parse_string(data, offset)?;
    let (uri, _) = parse_string(data, offset)?;

    // ── String validation ───────────────────────────────────────────────
    if name.is_empty() || name.len() > 32 {
        return Err(ZupyTokenError::InvalidMetadataName.into());
    }
    if symbol.is_empty() || symbol.len() > 10 {
        return Err(ZupyTokenError::InvalidMetadataSymbol.into());
    }
    if uri.is_empty() || uri.len() > 200 {
        return Err(ZupyTokenError::InvalidMetadataUri.into());
    }

    // ── Metadata account validation (treasury + mint + token_program) ────
    let bump = validate_metadata_accounts(
        program_id, authority, token_state_account, mint, token_program,
    )?;

    // ── CPI: Initialize metadata (token_state PDA signs) ────────────────
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 2] = [
        Seed::from(TOKEN_STATE_SEED),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_initialize_metadata(
        mint,
        token_state_account,
        token_program,
        name,
        symbol,
        uri,
        &[signer],
    )?;

    Ok(())
}
