use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::validate_id_pda;
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::helpers::v1_transfer::{
    invoke_v1_transfer_signed, validate_v1_authority, validate_v1_consolidation_payload,
};

/// Index of the first V1 cToken CPI account (`fee_payer`, then `authority`, …).
pub const CONSOLIDATE_V1_CPI_ACCOUNTS_START: usize = 4;

/// `owner_kind` byte: the leaves belong to a customer PDA (`[USER_SEED, id, bump]`).
pub const OWNER_KIND_USER: u8 = 0;
/// `owner_kind` byte: the leaves belong to a store PDA (`[COMPANY_SEED, id, bump]`).
pub const OWNER_KIND_COMPANY: u8 = 1;

/// Process `consolidate_leaves` (story 3.40, PO 2026-09-30).
///
/// Merges 2..=8 compressed Z$ leaves of ONE owner (customer PDA or store PDA)
/// into ONE leaf of the SAME owner: same mint, exact sum, no fee leg, no burn.
/// The backend builds the cToken V1 TRANSFER (inputs + validity proof, one
/// output); this instruction validates it and signs with the owner PDA seeds.
///
/// Why: a V1 transfer carries one proof for all its inputs, and a client spend
/// or a store reward must fit in 1,232 bytes; a balance scattered across small
/// leaves cannot be spent even when the total is enough (the backend picks the
/// largest leaf ≥ amount and fails otherwise). Merging first restores a single
/// spendable leaf. Same mechanism as the working transfers — no new CPI.
///
/// Accounts (6+):
/// ```text
///   0. transfer_authority (signer)   — must match token_state.transfer_authority
///   1. token_state (read)
///   2. mint (read)                   — must equal token_state.mint and the payload mint
///   3. owner_pda (read)              — owner of every input leaf AND of the output leaf
///   4+ V1 cToken CPI accounts, same order as `transfer_company_to_user`'s tail:
///      fee_payer, authority (= owner_pda), cpi_authority_pda, light_system_program,
///      registered_program_pda, noop, account_compression_authority,
///      account_compression_program, self_program (cToken), token_pool (None),
///      compress_or_decompress_account (None), token_program (None), system_program,
///      then the Merkle tree(s) + queue(s) the payload indexes.
/// ```
///
/// Data (after the 8-byte discriminator):
/// ```text
///   [0]      owner_kind u8 — 0 = customer (USER_SEED), 1 = store (COMPANY_SEED)
///   [1..9]   owner_id u64 LE
///   [9]      owner_bump u8
///   [10..18] amount u64 LE — the sum of the input leaves = the single output
///   [18..]   memo (u32 LE len + utf8) — "zupy:v1:consolidate:<id>" (operation id)
///   [..]     V1 TRANSFER cToken data (disc + Vec<u8> Borsh), see
///            `validate_v1_consolidation_payload`
/// ```
///
/// Discriminator: [131, 243, 51, 130, 117, 203, 4, 156] (SHA256("global:consolidate_leaves")[..8]).
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < CONSOLIDATE_V1_CPI_ACCOUNTS_START {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let owner_pda = &accounts[3];
    let cpi_accounts = &accounts[CONSOLIDATE_V1_CPI_ACCOUNTS_START..];

    // ── Parse instruction data ──────────────────────────────────────────
    let owner_kind = parse_u8(data, 0)?;
    let owner_id = parse_u64(data, 1)?;
    let owner_bump = parse_u8(data, 9)?;
    let amount = parse_u64(data, 10)?;
    let (memo, v1_offset) = parse_string(data, 18)?;
    let v1_data = &data[v1_offset..];

    let seed: &[u8] = match owner_kind {
        OWNER_KIND_USER => USER_SEED,
        OWNER_KIND_COMPANY => COMPANY_SEED,
        _ => return Err(ProgramError::InvalidInstructionData),
    };

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Common transfer validation (checks 1–8) ─────────────────────────
    validate_transfer_common_compressed(program_id, token_state_account, transfer_authority, mint)?;

    // ── The owner PDA derives from (kind, id, bump) ─────────────────────
    validate_id_pda(owner_pda.address(), seed, owner_id, owner_bump, program_id)?;

    // ── The payload is a consolidation of the owner's leaves, nothing else ─
    validate_v1_consolidation_payload(v1_data, mint.address(), owner_pda.address(), amount)?;
    validate_v1_authority(cpi_accounts, owner_pda)?;

    // ── ONE CPI: V1 TRANSFER owner → owner, owner PDA signs ─────────────
    let owner_id_bytes = owner_id.to_le_bytes();
    let bump_bytes = [owner_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(seed),
        Seed::from(owner_id_bytes.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    invoke_v1_transfer_signed(cpi_accounts, owner_pda, v1_data, &[Signer::from(&signer_seeds)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_enough_account_keys() {
        let program_id = Address::from([1u8; 32]);
        let result = process(&program_id, &[], &[0u8; 32]);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn owner_kinds_are_distinct() {
        assert_ne!(OWNER_KIND_USER, OWNER_KIND_COMPANY);
    }
}
