use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, LIGHT_TOKEN_CPI_AUTHORITY, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{cpi_compress_from_spl, derive_spl_interface_pda};
use crate::helpers::instruction_data::{parse_string, parse_u64};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::validate_pda;
use crate::helpers::transfer_validation::{read_token_balance, validate_transfer_common};
use crate::state::token_state::TokenState;

/// Process `transfer_from_pool` instruction (compressed token version).
///
/// Compresses tokens from the distribution pool ATA into a compressed balance
/// (Merkle-tree leaf) for the recipient. The recipient does NOT receive an ATA —
/// they receive a Light Protocol compressed token leaf instead. This reduces cost
/// from ~0.00207 SOL to ~0.000005 SOL per recipient.
///
/// Uses `compress_spl_token_account` (Path A — no ZK proof required): appends a new
/// leaf to the Merkle tree without reading any existing compressed account.
/// Anchor 8-byte discriminator `[112, 230, 105, 101, 145, 202, 157, 97]`
/// (cu=2064, log "Instruction: CompressSplTokenAccount").
///
/// Accounts (16 minimum, plus ≥1 remaining Merkle tree accounts):
///   0.  transfer_authority         (signer)           — must match TRANSFER_AUTHORITY_PUBKEY
///   1.  token_state                (read)             — our program's token_state PDA
///   2.  mint                       (read)             — ZUPY Token-2022 mint
///   3.  pool_ata                   (writable)         — distribution pool ATA (source)
///   4.  recipient                  (read)             — who receives the compressed leaf
///   5.  fee_payer                  (writable, signer) — pays Light Protocol rent/fees
///   6.  token_program              (read)             — Token-2022 program
///   7.  system_program             (read)             — System program
///   8.  compressed_token_program   (read)             — Light cToken program
///   9.  cpi_authority_pda          (read)             — LIGHT_TOKEN_CPI_AUTHORITY
///   10. light_system_program       (read)             — LIGHT_SYSTEM_PROGRAM_ID
///   11. registered_program_pda     (read)             — REGISTERED_PROGRAM_PDA
///   12. noop_program               (read)             — SPL_NOOP_ID
///   13. account_compression_authority (read)          — ACCOUNT_COMPRESSION_AUTHORITY
///   14. account_compression_program  (read)           — ACCOUNT_COMPRESSION_PROGRAM_ID
///   15. spl_interface_pda          (writable)         — Light SPL pool PDA (seeds=[b"pool", mint])
///   16+ Merkle tree output queue   (writable)         — injected by JS client
///
/// Data: amount (u64, bytes 0–7) + memo (String, bytes 8+)
/// Discriminator: `[136, 167, 45, 66, 74, 252, 0, 16]` (SHA256("global:transfer_from_pool"))
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (16 accounts minimum) ─────────────────────────
    if accounts.len() < 16 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let transfer_authority           = &accounts[0];
    let token_state_account          = &accounts[1];
    let mint                         = &accounts[2];
    let pool_ata                     = &accounts[3];
    let recipient                    = &accounts[4];
    let fee_payer                    = &accounts[5];
    let token_program                = &accounts[6];
    let system_program               = &accounts[7];
    let compressed_token_prog        = &accounts[8];
    let cpi_authority_pda            = &accounts[9];
    let light_system_program         = &accounts[10];
    let registered_program_pda       = &accounts[11];
    let noop_program                 = &accounts[12];
    let account_compression_authority = &accounts[13];
    let account_compression_program  = &accounts[14];
    let spl_interface_pda            = &accounts[15];

    // ── Parse instruction data ──────────────────────────────────────────
    let amount = parse_u64(data, 0)?;
    let (memo, _) = parse_string(data, 8)?;

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Common transfer validation (9 checks, Spec §7.1-§7.8) ───────────
    let validation = validate_transfer_common(
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

    // ── Verify cpi_authority_pda is the canonical cToken CPI PDA ─────────
    let expected_ctoken_auth = Address::from(LIGHT_TOKEN_CPI_AUTHORITY);
    if cpi_authority_pda.address() != &expected_ctoken_auth {
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── Read token_state for pool_ata validation ────────────────────────
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // ── Pool ATA validation ─────────────────────────────────────────────
    if pool_ata.address().as_ref() != state.pool_ata() {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }
    // Pool ATA must be owned by Token-2022 (Spec §7.1)
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !pool_ata.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }

    // ── Balance check ───────────────────────────────────────────────────
    let pool_balance = read_token_balance(pool_ata);
    if pool_balance < amount {
        return Err(ZupyTokenError::InsufficientPoolBalance.into());
    }

    // ── Validate spl_interface_pda address ──────────────────────────────
    let mint_key: [u8; 32] = mint.address().as_ref().try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let (expected_spl_pda, _) = derive_spl_interface_pda(&mint_key);
    validate_pda(spl_interface_pda.address(), &expected_spl_pda)?;

    // ── Encode recipient owner ───────────────────────────────────────────
    let owner: &[u8; 32] = recipient.address().as_ref().try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // remaining_amount = pool_balance - amount (SPL to keep in pool_ata)
    let remaining_amount = pool_balance - amount;

    // ── CPI: Compress from Pool ATA → compressed leaf for recipient ──────
    // token_state PDA signs with [TOKEN_STATE_SEED, &[bump]]
    let bump_bytes = [validation.bump];
    let signer_seeds: [Seed; 2] = [
        Seed::from(TOKEN_STATE_SEED),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_compress_from_spl(
        compressed_token_prog,
        cpi_authority_pda,
        light_system_program,
        registered_program_pda,
        noop_program,
        account_compression_authority,
        account_compression_program,
        fee_payer,
        token_state_account,        // authority: token_state PDA that owns pool_ata
        spl_interface_pda,          // token_pool_pda
        pool_ata,                   // source_ata
        token_program,
        system_program,
        owner,
        Some(remaining_amount),
        &accounts[16..],            // remaining: Merkle tree output queue
        &[signer],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify account count check: at least 16 accounts required.
    /// Passing zero accounts (or any count < 16) must return NotEnoughAccountKeys.
    #[test]
    fn test_process_returns_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 16];
        // Empty slice — account count check fires immediately
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }
}
