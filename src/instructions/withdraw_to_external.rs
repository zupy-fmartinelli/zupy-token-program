use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{cpi_decompress_to_spl, derive_spl_interface_pda};
use crate::helpers::cpi::cpi_create_ata_if_needed;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{validate_pda, validate_pda_with_seeds};
use crate::helpers::transfer_validation::{
    validate_destination_ata_if_exists, validate_transfer_common,
};

/// Process `withdraw_to_external` instruction (#18).
///
/// Decompresses a user's compressed ZUPY balance into an external wallet's ATA.
/// The external wallet is NOT a PDA — it's a regular Solana address (Phantom, Trezor, etc.).
///
/// NOTE: withdraw_to_external is the ONLY instruction that creates an ATA since the compressed
/// token migration. All other transfer instructions use only compressed accounts for both source
/// and destination. This instruction must create the dest_ata because external wallets are not
/// PDAs and have no on-chain compressed-account storage.
///
/// Accounts (13 minimum):
///   0. transfer_authority       (signer)           — Backend authority (Vault Transit)
///   1. token_state              (read)             — Program state PDA
///   2. mint                     (read)             — ZUPY mint (Token-2022)
///   3. user_pda                 (read)             — Source user PDA (signs decompress CPI)
///   4. dest_wallet              (read)             — External wallet address (NOT a PDA)
///   5. dest_ata                 (writable)         — Destination ATA (created if needed)
///   6. fee_payer                (writable, signer) — Pays ATA rent + Light Protocol fees
///   7. token_program            (read)             — Token-2022 Program
///   8. associated_token_program (read)             — ATA Program (required for ATA creation)
///   9. system_program           (read)             — System Program
///   10. compressed_token_program (read)            — Light cToken Program
///   11. compressed_token_authority (read)          — Light cToken authority PDA
///   12. spl_interface_pda       (writable)         — Light SPL pool PDA (seeds=[b"pool", mint])
///   13+ Light system accounts                      — Merkle tree, nullifier queue, noop (client-injected)
///
/// Data: amount (u64, bytes 0–7) + user_id (u64, bytes 8–15) + user_bump (u8, byte 16) + memo (String, bytes 17+)
/// Discriminator: [114, 198, 185, 119, 169, 163, 29, 251] (SHA256("global:withdraw_to_external"))
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // 1. Account count check (MUST be first)
    if accounts.len() < 13 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // 2. Unpack accounts
    let transfer_authority    = &accounts[0];
    let token_state           = &accounts[1];
    let mint                  = &accounts[2];
    let user_pda              = &accounts[3];
    let dest_wallet           = &accounts[4];
    let dest_ata              = &accounts[5];
    let fee_payer             = &accounts[6];
    let token_program         = &accounts[7];
    // accounts[8] = associated_token_program — must be in tx accounts list for the ATA CPI
    //               at runtime; not extracted by handler (cpi_create_ata_if_needed uses hardcoded ID).
    let system_program        = &accounts[9];
    let compressed_token_prog = &accounts[10];
    let compressed_token_auth = &accounts[11];
    let spl_interface_pda     = &accounts[12];

    // 3. Parse instruction data (UNCHANGED)
    let amount    = parse_u64(data, 0)?;
    let user_id   = parse_u64(data, 8)?;
    let user_bump = parse_u8(data, 16)?;
    let (memo, _) = parse_string(data, 17)?;

    // 4. Validate zero amount (UNCHANGED)
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }

    // 5. Validate memo (UNCHANGED)
    validate_memo_format(memo)?;

    // 6. Common transfer validation — 9 standard security checks (UNCHANGED)
    validate_transfer_common(
        program_id,
        token_state,
        transfer_authority,
        mint,
        token_program,
    )?;

    // 7. Validate user PDA with client-provided bump (UNCHANGED)
    let user_id_bytes = user_id.to_le_bytes();
    validate_pda_with_seeds(
        user_pda.address(),
        &[USER_SEED, &user_id_bytes, &[user_bump]],
        program_id,
    )?;

    // 8. Validate fee_payer is a signer (same pattern as other compressed instructions)
    if !fee_payer.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // 9. Validate compressed_token_program is the Light cToken program
    let expected_ctoken: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    if compressed_token_prog.address() != &expected_ctoken {
        return Err(ProgramError::IncorrectProgramId);
    }

    // 10. Validate existing dest_ata if present (mint check) — no-op if account has no data (AC3)
    validate_destination_ata_if_exists(dest_ata, mint.address())?;

    // 11. Create dest_ata for external wallet if it doesn't exist
    // NOTE: withdraw_to_external is the ONLY instruction that creates an ATA since the compressed
    // token migration. All other transfer instructions use compressed accounts for both source and
    // destination. This instruction must create the dest_ata because the external wallet is not a
    // PDA and cannot hold compressed tokens directly.
    cpi_create_ata_if_needed(
        dest_ata,
        fee_payer,    // pays ATA rent (~0.002 SOL) — NOT transfer_authority
        dest_wallet,  // owner (external wallet — NOT a PDA)
        mint,
        token_program,
        system_program,
    )?;

    // 12. Derive + validate spl_interface_pda address; extract bump for CPI (AC1)
    let mint_key: [u8; 32] = mint.address().as_ref().try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let (expected_spl_pda, spl_bump) = derive_spl_interface_pda(&mint_key);
    validate_pda(spl_interface_pda.address(), &expected_spl_pda)?;

    // 13. Decompress: user compressed balance → dest_ata (external wallet's ATA) (AC1)
    // user_pda signs with 3-seed pattern — identical to former cpi_transfer_checked call
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
        dest_ata,          // destination SPL (external wallet's ATA)
        user_pda,          // authority (source owner, signs decompress)
        spl_interface_pda,
        token_program,
        system_program,
        amount,
        spl_bump,
        &accounts[13..],   // remaining Light system accounts (Merkle tree, nullifier queue, noop)
        &[signer],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify new account count check: at least 13 accounts required.
    /// Passing zero accounts (or any count < 13) must return NotEnoughAccountKeys.
    #[test]
    fn test_process_returns_not_enough_account_keys() {
        let program_id = Address::default();
        let data = [0u8; 17];
        // Empty slice — account count check fires immediately (accounts.len() < 13)
        let result = process(&program_id, &[], &data);
        assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    }


}
