use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, INCENTIVE_POOL_SEED, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::pda::{validate_light_ctoken_program, validate_id_pda, validate_pda_with_seeds};
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::helpers::v1_transfer::{
    invoke_v1_transfer_signed, validate_v1_authority, validate_v1_transfer_payload, V1Leg,
};
use crate::instructions::split_math::checked_total;

/// Index of the first V1 cToken CPI account (`fee_payer`, then `authority`, …).
pub const SPLIT_V1_CPI_ACCOUNTS_START: usize = 9;

/// Process `execute_split_transfer` instruction.
///
/// **Burn-free explicit-amount split (AD-A1 / AD-A2, D-51).** The split is
/// computed OFF-CHAIN in the ledger; this program executes the amounts it is
/// handed and invents nothing. There is **no burn** — money is conserved:
///   User (compressed leaves) → Company (`company_amount`) + Incentive Pool (`pool_amount`)
///
/// ## 2026-09-29 (story 3.21) — why this changed, MEASURED
///
/// Up to `396df04` (deployed 2026-08-22) this instruction made two
/// `cpi_compressed_transfer` calls (cToken disc=3, no proof). An unsigned
/// mainnet simulation (story 3.17, `3-17-evidence/mainnet-simulate-new_1_0.json`)
/// fails that CPI with `Custom(18063) InvalidTokenOwner`: disc=3 moves cToken
/// *Solana accounts*, and Z$ lives in *compressed leaves* owned by our PDAs.
/// It now forwards ONE V1 TRANSFER (`global:transfer`, with validity proof) —
/// the mechanism `transfer_company_to_user` uses successfully on mainnet — with
/// outputs `[company, pool (if > 0), change back to user (optional)]`, signed
/// by the user PDA. One CPI keeps it atomic and needs a single proof (a change
/// leaf created by a first CPI would have no proof inside the same slot).
///
/// Accounts (11+):
/// ```text
///   0. transfer_authority (signer)
///   1. token_state (read)
///   2. mint (read)                      — validated; never burned
///   3. user_pda (read)                  — owner of the input leaves / PDA signer
///   4. company_pda (read)               — owner of output 0 (`company_amount`)
///   5. incentive_pool_pda (read)        — owner of output 1 (`pool_amount`, if > 0)
///   6. fee_payer (writable, signer)     — kept for layout compatibility (3.17 adapter)
///   7. system_program (read)            — kept for layout compatibility
///   8. compressed_token_program (read)  — cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
///   9+. V1 cToken CPI accounts, same order as `transfer_company_to_user` [5..]:
///       fee_payer, authority (= user_pda), cpi_authority_pda, light_system_program,
///       registered_program_pda, noop, account_compression_authority,
///       account_compression_program, self_program (cToken), token_pool (cToken = None),
///       compress_or_decompress_account (cToken = None), token_program (cToken = None),
///       system_program, then the Merkle tree(s) + queue(s) the payload indexes.
/// ```
///
/// Data (after the 8-byte discriminator):
/// ```text
///   [0..8]  user_id u64 · [8..16] company_id u64
///   [16..24] company_amount u64 · [24..32] pool_amount u64
///   [32] user_bump · [33] company_bump · [34] incentive_bump
///   [35..]  operation_type (u32 LE len + utf8) — `z_direct` | `mixed_payment`
///   [..]    V1 TRANSFER cToken data (disc + Vec<u8> Borsh) — see `validate_v1_transfer_payload`
/// ```
///
/// The header is byte-identical to `396df04` (the 3.17 adapter already sends it);
/// a caller that sends only the header now fails with `InvalidInstructionData`
/// BEFORE any CPI.
///
/// Discriminator: [51, 254, 61, 214, 234, 138, 101, 214] — UNCHANGED.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (9 accounts minimum before the V1 CPI tail) ───
    if accounts.len() < SPLIT_V1_CPI_ACCOUNTS_START {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let user_pda = &accounts[3];           // owner of the input leaves / PDA signer
    let company_pda = &accounts[4];        // output 0
    let incentive_pool_pda = &accounts[5]; // output 1 (when pool_amount > 0)
    let compressed_token_program = &accounts[8];
    let cpi_accounts = &accounts[SPLIT_V1_CPI_ACCOUNTS_START..];

    // ── Parse instruction data ──────────────────────────────────────────
    let user_id_u64 = parse_u64(data, 0)?;
    let company_id_u64 = parse_u64(data, 8)?;
    let company_amount = parse_u64(data, 16)?;
    let pool_amount = parse_u64(data, 24)?;
    let user_bump = parse_u8(data, 32)?;
    let company_bump = parse_u8(data, 33)?;
    let incentive_bump = parse_u8(data, 34)?;
    let (operation_type, v1_offset) = parse_string(data, 35)?;
    let v1_data = &data[v1_offset..];

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

    // ── The V1 payload must move exactly these legs, nothing else ───────
    // Pool leg skipped when pool_amount == 0 (taxa_pool = 0, AD-A2).
    let company_leg = V1Leg { owner: company_pda.address(), amount: company_amount };
    let pool_leg = V1Leg { owner: incentive_pool_pda.address(), amount: pool_amount };
    let both = [company_leg, pool_leg];
    let legs: &[V1Leg] = if pool_amount > 0 { &both } else { &both[..1] };
    validate_v1_transfer_payload(v1_data, mint.address(), user_pda.address(), legs)?;
    validate_v1_authority(cpi_accounts, user_pda)?;

    // ── ONE CPI: V1 TRANSFER user → [company, pool, change], user PDA signs ─
    let user_bump_bytes = [user_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(USER_SEED),
        Seed::from(user_id_bytes.as_ref()),
        Seed::from(user_bump_bytes.as_ref()),
    ];
    invoke_v1_transfer_signed(cpi_accounts, user_pda, v1_data, &[Signer::from(&signer_seeds)])

    // No burn leg (AD-A2 / D-51): money is conserved, never destroyed on-chain.
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
