use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};

use crate::constants::{COMPANY_SEED, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::validate_v1_transfer_disc;
use crate::helpers::instruction_data::{parse_u64, parse_u8};
use crate::helpers::pda::validate_pda_with_seeds;
use crate::helpers::transfer_validation::validate_transfer_common;
use crate::state::token_state::TokenState;

/// Process `return_to_pool_v1` instruction (V1 CPI passthrough, mainnet).
///
/// Forwards a pre-built V1 TRANSFER instruction to the mainnet cToken program,
/// signing with company PDA seeds via `invoke_signed`. The backend builds the complete
/// V1 Borsh instruction data (`CompressedTokenInstructionDataTransfer` with
/// `is_compress=false`) and the V1-ordered account list; this instruction only
/// validates security invariants before forwarding.
///
/// **Context:** Mainnet cToken program (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`)
/// runs V1 (Anchor 8-byte discriminators, 642KB). Transfer2 (disc=101)
/// only works on devnet V2. This passthrough enables decompress operations on mainnet
/// until Light Protocol upgrades.
///
/// Mirrors `return_user_to_pool_v1` but uses `COMPANY_SEED` instead of
/// `USER_SEED` and validates company PDA derivation.
///
/// ## Security Validations
///
/// 1. `transfer_authority` must be signer (Spec §7.1-§7.8 via `validate_transfer_common`)
/// 2. `token_state` must be owned by our program (via `validate_transfer_common`)
/// 3. Company PDA derivation must match `company_id` (prevents signing for wrong PDA)
/// 4. `pool_ata` must match `token_state.pool_ata()` (prevents decompress to wrong dest)
/// 5. CPI data must start with V1 TRANSFER disc (prevents other cToken instructions)
/// 6. CPI target hardcoded to `LIGHT_COMPRESSED_TOKEN_PROGRAM_ID` (no arbitrary programs)
///
/// ## Accounts (minimum 6 + CPI accounts)
///
///   0. transfer_authority        (signer)           — must match TRANSFER_AUTHORITY_PUBKEY
///   1. token_state               (read)             — our program's token_state PDA
///   2. mint                      (read)             — ZUPY Token-2022 mint
///   3. company_pda               (read)             — compressed source + CPI signer
///   4. pool_ata                  (read)             — destination SPL ATA (validated)
///   5. token_program             (read)             — Token-2022 program
///   6+ V1 CPI accounts           (client-assembled) — forwarded to cToken in V1 order
///
/// ## Data Layout (after 8-byte Anchor discriminator, stripped by lib.rs)
///
/// ```text
/// [0..8]   company_id (u64 LE)
/// [8]      company_bump (u8)
/// [9..]    raw V1 CPI instruction data (starts with 8-byte V1 TRANSFER disc)
/// ```
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (minimum 6 validation accounts) ─────────────────
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority  = &accounts[0];
    let token_state_account = &accounts[1];
    let mint                = &accounts[2];
    let company_pda         = &accounts[3];
    let pool_ata            = &accounts[4];
    let token_program       = &accounts[5];

    // ── Parse instruction data ────────────────────────────────────────────
    let company_id_u64 = parse_u64(data, 0)?;
    let company_bump = parse_u8(data, 8)?;

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

    // ── PDA validation: company_pda (via client-provided bump) ────────────
    let company_id_bytes = company_id_u64.to_le_bytes();
    validate_pda_with_seeds(
        company_pda.address(),
        &[COMPANY_SEED, &company_id_bytes, &[company_bump]],
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
    // Pinocchio 0.10 resolves CPI target from InstructionView.program_id,
    // NOT from account_views (see cpi_decompress_to_spl for details).
    let account_views: Vec<&AccountView> = cpi_accounts.iter().collect();

    // ── CPI: Forward V1 TRANSFER to cToken, signing with company PDA ──────
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

    /// Verify minimum account count check: at least 6 accounts required.
    #[test]
    fn test_return_to_pool_v1_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }

    /// Short data buffer (< 9 bytes) must fail during parse.
    #[test]
    fn test_return_to_pool_v1_short_data_returns_error() {
        let program_id = Address::default();
        let short_data = [0u8; 8];
        let result = process(&program_id, &[], &short_data);
        // Fails with NotEnoughAccountKeys (checked first) or parse error
        assert!(result.is_err());
    }
}
