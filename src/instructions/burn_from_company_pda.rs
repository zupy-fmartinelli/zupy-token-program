use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::cpi_compressed_burn;
use crate::helpers::instruction_data::{parse_string, parse_u64};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{derive_company_pda, validate_pda};
use crate::helpers::transfer_validation::validate_transfer_common_compressed;

/// Process `burn_from_company_pda` instruction (compressed version).
///
/// Burns company compressed balance via Light Protocol BurnCpi (Path C).
/// company_pda signs as authority over its compressed leaf.
///
/// Accounts (7 minimum):
///   0. transfer_authority        (signer)           — must match TRANSFER_AUTHORITY_PUBKEY
///   1. token_state               (read)             — our program's token_state PDA
///   2. mint                      (writable)         — ZUPY Token-2022 mint (supply decrement)
///   3. company_pda               (read)             — compressed source + CPI authority
///   4. fee_payer                 (writable, signer) — pays Light Protocol rent/fees
///   5. system_program            (read)             — System program
///   6. compressed_token_program  (read)             — Light cToken program
///   7+ Light system accounts                        — Merkle tree, nullifier queue, noop (client-injected)
///
/// Data: company_id_u64 (0-7) + amount (8-15) + memo (16+)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (7 accounts minimum) ─────────────────────────
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority    = &accounts[0];
    let token_state_account   = &accounts[1];
    let mint                  = &accounts[2];
    let company_pda           = &accounts[3];
    let fee_payer             = &accounts[4];
    let system_program        = &accounts[5];
    let compressed_token_prog = &accounts[6];

    // ── Parse instruction data ──────────────────────────────────────────
    let company_id_u64 = parse_u64(data, 0)?;
    let amount = parse_u64(data, 8)?;
    let (memo, _) = parse_string(data, 16)?;

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Common transfer validation (8 checks — compressed variant, no token_program) ─
    // Checks 1–8 from validate_transfer_common; check 9 (token_program == Token-2022)
    // is inapplicable: no ATA operations, Light Protocol handles token accounting.
    validate_transfer_common_compressed(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
    )?;

    // ── Additional signer check: fee_payer ──────────────────────────────
    if !fee_payer.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Verify system_program is the System Program ──────────────────────
    let expected_system: Address = SYSTEM_PROGRAM_ID.into();
    if system_program.address() != &expected_system {
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── Verify compressed_token_program is the Light cToken program ──────
    let expected_ctoken: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    if compressed_token_prog.address() != &expected_ctoken {
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── PDA validation: company_pda ─────────────────────────────────────
    let company_id_bytes = company_id_u64.to_le_bytes();
    let (expected_company_pda, company_bump) = derive_company_pda(program_id, company_id_u64);
    validate_pda(company_pda.address(), &expected_company_pda)?;

    // ── CPI: Burn company compressed balance via Light Protocol ──────────
    // company_pda signs with 3-seed pattern (COMPANY_SEED + company_id + bump)
    let bump_bytes = [company_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(COMPANY_SEED),
        Seed::from(company_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_compressed_burn(
        compressed_token_prog,
        fee_payer,
        company_pda,
        mint,
        system_program,
        amount,
        &accounts[7..],
        &[signer],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify new account count check: at least 7 accounts required.
    /// Passing fewer than 7 accounts must return NotEnoughAccountKeys.
    #[test]
    fn test_burn_from_company_pda_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }
}
