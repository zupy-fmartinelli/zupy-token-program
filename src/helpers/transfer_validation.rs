use pinocchio::AccountView;
use pinocchio::Address;
use pinocchio::ProgramResult;
use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;

use crate::constants::{TOKEN_2022_PROGRAM_ID, TOKEN_DECIMALS, TOKEN_STATE_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::{cpi_create_ata_if_needed, cpi_transfer_checked};
use crate::helpers::pda::validate_pda_with_seeds;
use crate::state::token_state::{TokenState, TOKEN_STATE_SIZE};

/// Result of common transfer validation: returns the TokenState bump for PDA signing.
#[derive(Debug)]
pub struct TransferValidationResult {
    pub bump: u8,
}

/// Base token_state validation shared by ALL instructions that read token_state.
///
/// Validates (in order):
/// 1. token_state owned by our program (Spec §7.1)
/// 2. token_state data length >= TOKEN_STATE_SIZE (Spec §7.7)
/// 3. token_state PDA matches `[TOKEN_STATE_SEED, &[bump]]` via stored bump (Spec §7.2)
/// 4. token_state.initialized == true → NotInitialized (6010)
///
/// Does NOT check paused or authority — those are instruction-specific.
/// Returns the stored bump for use in PDA signing.
pub fn validate_token_state_base(
    program_id: &Address,
    token_state_account: &AccountView,
) -> Result<u8, ProgramError> {
    // §7.1 — token_state owned by our program
    if !token_state_account.owned_by(program_id) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // §7.7 — data length check
    if token_state_account.data_len() < TOKEN_STATE_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }

    // Zero-copy read (safe: single-threaded Solana runtime)
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // §7.2 — PDA validation via stored bump
    let bump = state.bump();
    let expected_pda =
        Address::create_program_address(&[TOKEN_STATE_SEED, &[bump]], program_id)
            .map_err(|_| ZupyTokenError::InvalidPDA)?;
    if token_state_account.address() != &expected_pda {
        return Err(ZupyTokenError::InvalidPDA.into());
    }

    // §7.4 — initialized check
    if !state.initialized() {
        return Err(ZupyTokenError::NotInitialized.into());
    }

    Ok(bump)
}

/// Common transfer validation applied to ALL 4 hot-path transfer instructions.
///
/// Validates (in order):
/// 1–4. Base token_state checks via `validate_token_state_base`
/// 5. token_state.paused == false → SystemPaused (6018)
/// 6. token_state.transfer_authority == transfer_authority → InvalidAuthority (6000)
/// 7. mint owned by Token-2022 (Spec §7.1)
/// 8. token_state.mint == mint.address() → InvalidMint (6011)
/// 9. token_program is Token-2022 program ID (Spec §7.8)
///
/// Returns the token_state bump for use in PDA signing.
pub fn validate_transfer_common(
    program_id: &Address,
    token_state_account: &AccountView,
    transfer_authority: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
) -> Result<TransferValidationResult, ProgramError> {
    // 1–4. Base token_state validation
    let bump = validate_token_state_base(program_id, token_state_account)?;

    // Read state for remaining checks
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // 5. not paused
    if state.paused() {
        return Err(ZupyTokenError::SystemPaused.into());
    }

    // 6. transfer_authority matches
    if !transfer_authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    if state.transfer_authority() != transfer_authority.address().as_ref() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // 7. mint owned by Token-2022
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !mint.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // 8. token_state.mint matches
    if state.mint() != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // 9. token_program is Token-2022
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    Ok(TransferValidationResult { bump })
}

/// Common validation for compressed-token transfer instructions.
///
/// Performs checks 1–8 from `validate_transfer_common` — all except check 9
/// (token_program is Token-2022), which is inapplicable for compressed instructions
/// that do not perform ATA operations. The caller must separately verify that the
/// `compressed_token_program` account is the Light cToken program.
///
/// Validates (in order):
/// 1–4. Base token_state checks via `validate_token_state_base`
/// 5. token_state.paused == false → SystemPaused
/// 6. transfer_authority is signer + matches token_state.transfer_authority
/// 7. mint owned by Token-2022 (mint account is still the Token-2022 mint)
/// 8. token_state.mint == mint.address()
///
/// Returns the token_state bump for PDA signing.
pub fn validate_transfer_common_compressed(
    program_id: &Address,
    token_state_account: &AccountView,
    transfer_authority: &AccountView,
    mint: &AccountView,
) -> Result<TransferValidationResult, ProgramError> {
    // 1–4. Base token_state validation
    let bump = validate_token_state_base(program_id, token_state_account)?;

    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // 5. not paused
    if state.paused() {
        return Err(ZupyTokenError::SystemPaused.into());
    }

    // 6. transfer_authority matches
    if !transfer_authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    if state.transfer_authority() != transfer_authority.address().as_ref() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // 7. mint owned by Token-2022
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !mint.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // 8. token_state.mint matches
    if state.mint() != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    Ok(TransferValidationResult { bump })
}

/// Validate common metadata instruction accounts.
///
/// Shared by `initialize_metadata` and `update_metadata_field`.
/// Validates:
/// 1. Base token_state (ownership, PDA, initialized)
/// 2. Treasury authorization (signer + address match)
/// 3. Mint owned by Token-2022 + mint address matches token_state
/// 4. token_program is Token-2022
///
/// Returns the token_state bump for PDA signing.
pub fn validate_metadata_accounts(
    program_id: &Address,
    authority: &AccountView,
    token_state_account: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
) -> Result<u8, ProgramError> {
    // Base token_state validation
    validate_token_state_base(program_id, token_state_account)?;

    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // Treasury authorization
    if !authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    let authority_key: &[u8; 32] = authority.address().as_ref().try_into().unwrap();
    if !state.is_treasury(authority_key) {
        return Err(ZupyTokenError::UnauthorizedTreasury.into());
    }

    // Mint validation
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !mint.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidMint.into());
    }
    if state.mint() != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // Token program check
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    Ok(state.bump())
}

/// Validate NFT minting payer authorization.
///
/// Shared by `create_coupon_nft`, `create_zupy_card`, and `mint_coupon_cnft`.
/// Validates:
/// 1. Payer is signer
/// 2. Base token_state (ownership, PDA, initialized)
/// 3. Payer matches token_state.mint_authority (AUDIT 12.1)
pub fn validate_nft_payer(
    program_id: &Address,
    payer: &AccountView,
    token_state_account: &AccountView,
) -> Result<(), ProgramError> {
    if !payer.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    validate_token_state_base(program_id, token_state_account)?;

    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });
    let payer_key: &[u8; 32] = payer.address().as_ref().try_into().unwrap();
    if !state.is_mint_authority(payer_key) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    Ok(())
}

/// Read token balance from a Token account (zero-copy, offset 64, u64 LE).
///
/// # Safety contract
/// Caller MUST verify the account is owned by Token-2022 before calling.
/// Token-2022-owned accounts are guaranteed >= 165 bytes (SPL Token account layout),
/// so indexing bytes 64..72 is safe. The Solana runtime is single-threaded,
/// guaranteeing no concurrent borrows.
#[inline(always)]
pub fn read_token_balance(account: &AccountView) -> u64 {
    let data = unsafe { account.borrow_unchecked() };
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

/// Read token account owner pubkey (bytes 32..64).
///
/// # Safety contract
/// Caller MUST verify the account is owned by Token-2022 before calling.
/// Token-2022-owned accounts are guaranteed >= 165 bytes (SPL Token account layout),
/// so indexing bytes 32..64 is safe. The Solana runtime is single-threaded,
/// guaranteeing no concurrent borrows.
#[inline(always)]
pub fn read_token_owner(account: &AccountView) -> &[u8] {
    unsafe { &account.borrow_unchecked()[32..64] }
}

/// Read token account mint pubkey (bytes 0..32).
///
/// # Safety contract
/// Caller MUST verify the account is owned by Token-2022 before calling.
/// Token-2022-owned accounts are guaranteed >= 165 bytes (SPL Token account layout),
/// so indexing bytes 0..32 is safe. The Solana runtime is single-threaded,
/// guaranteeing no concurrent borrows.
#[inline(always)]
pub fn read_token_mint(account: &AccountView) -> &[u8] {
    unsafe { &account.borrow_unchecked()[0..32] }
}

/// Validate that a source ATA's mint matches the expected mint and owner matches expected PDA.
pub fn validate_source_ata(
    ata: &AccountView,
    expected_mint: &Address,
    expected_owner: &Address,
) -> Result<(), ProgramError> {
    // ATA must be owned by Token-2022
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !ata.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // mint check
    if read_token_mint(ata) != expected_mint.as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // owner check
    if read_token_owner(ata) != expected_owner.as_ref() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    Ok(())
}

/// Validate a destination ATA if it already exists (data_len > 0).
/// Checks: Token-2022 ownership + mint match.
/// Skips validation if the account has no data (will be created via CPI).
pub fn validate_destination_ata_if_exists(
    ata: &AccountView,
    expected_mint: &Address,
) -> Result<(), ProgramError> {
    if ata.data_len() > 0 {
        let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
        if !ata.owned_by(&token_2022_addr) {
            return Err(ZupyTokenError::InvalidAuthority.into());
        }
        if read_token_mint(ata) != expected_mint.as_ref() {
            return Err(ZupyTokenError::InvalidMint.into());
        }
    }
    Ok(())
}

/// Execute a validated PDA-to-PDA token transfer.
///
/// Shared by `transfer_company_to_user` and `transfer_user_to_company`.
/// Handles the full flow after account extraction and data parsing:
/// 1. Input validation (amount != 0, memo format)
/// 2. Common transfer validation (9 checks via `validate_transfer_common`)
/// 3. Source + destination PDA validation (client-provided bumps)
/// 4. Source ATA ownership + mint + balance check
/// 5. Destination ATA validation (if exists)
/// 6. Create destination ATA if needed (CPI)
/// 7. TransferChecked CPI with source PDA as signer
#[inline(always)]
pub fn execute_pda_transfer(
    program_id: &Address,
    transfer_authority: &AccountView,
    token_state_account: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
    system_program: &AccountView,
    source_pda: &AccountView,
    source_ata: &AccountView,
    source_seed: &[u8],
    source_id_bytes: &[u8],
    source_bump: u8,
    dest_pda: &AccountView,
    dest_ata: &AccountView,
    dest_seed: &[u8],
    dest_id_bytes: &[u8],
    dest_bump: u8,
    amount: u64,
    memo: &str,
) -> ProgramResult {
    // ── Input validation ──────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    crate::helpers::memo::validate_memo_format(memo)?;

    // ── Common transfer validation (9 checks) ─────────────────────────
    validate_transfer_common(
        program_id,
        token_state_account,
        transfer_authority,
        mint,
        token_program,
    )?;

    // ── PDA validation: source ────────────────────────────────────────
    validate_pda_with_seeds(
        source_pda.address(),
        &[source_seed, source_id_bytes, &[source_bump]],
        program_id,
    )?;

    // ── PDA validation: destination ───────────────────────────────────
    validate_pda_with_seeds(
        dest_pda.address(),
        &[dest_seed, dest_id_bytes, &[dest_bump]],
        program_id,
    )?;

    // ── Source ATA validation ─────────────────────────────────────────
    validate_source_ata(source_ata, mint.address(), source_pda.address())?;

    // ── Balance check ─────────────────────────────────────────────────
    let balance = read_token_balance(source_ata);
    if balance < amount {
        return Err(ZupyTokenError::InsufficientBalance.into());
    }

    // ── Destination ATA validation (if already exists) ────────────────
    validate_destination_ata_if_exists(dest_ata, mint.address())?;

    // ── CPI: Create destination ATA if needed ─────────────────────────
    cpi_create_ata_if_needed(
        dest_ata,
        transfer_authority,
        dest_pda,
        mint,
        token_program,
        system_program,
    )?;

    // ── CPI: TransferChecked (source PDA signs) ───────────────────────
    let bump_bytes = [source_bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(source_seed),
        Seed::from(source_id_bytes),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_transfer_checked(
        source_ata,
        dest_ata,
        source_pda,
        mint,
        amount,
        TOKEN_DECIMALS,
        token_program.address(),
        &[signer],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
    use core::mem::size_of;
    use crate::state::token_state::{TokenStateMut, TOKEN_STATE_DISCRIMINATOR};
    use crate::constants::{COMPANY_SEED, PROGRAM_ID, USER_SEED};

    // ── Test helpers ────────────────────────────────────────────────────

    /// Build a RuntimeAccount buffer with trailing data.
    fn make_account_buf(
        address: [u8; 32],
        owner: [u8; 32],
        is_signer: bool,
        is_writable: bool,
        data_len: usize,
    ) -> (Vec<u64>, Vec<u8>) {
        // Separate data buffer for account data
        let data_buf = vec![0u8; data_len];

        // Allocate u64-aligned memory for RuntimeAccount
        let words = (size_of::<RuntimeAccount>() + 7) / size_of::<u64>() + 1;
        let mut buf = vec![0u64; words];

        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = is_signer as u8;
            (*raw).is_writable = is_writable as u8;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = Address::from(address);
            (*raw).owner = Address::from(owner);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = data_len as u64;
        }

        (buf, data_buf)
    }

    fn view_from_buf(buf: &mut Vec<u64>) -> AccountView {
        unsafe { AccountView::new_unchecked(buf.as_mut_ptr() as *mut RuntimeAccount) }
    }

    /// Build a properly initialized token_state account buffer with data inline.
    fn make_token_state_account(
        program_id_bytes: [u8; 32],
        transfer_auth: [u8; 32],
        mint_addr: [u8; 32],
        pool_ata_addr: [u8; 32],
        bump: u8,
        initialized: bool,
        paused: bool,
    ) -> Vec<u64> {
        // We need RuntimeAccount header + TOKEN_STATE_SIZE data bytes
        let header_size = size_of::<RuntimeAccount>();
        let total_bytes = header_size + TOKEN_STATE_SIZE;
        let words = (total_bytes + 7) / 8;
        let mut buf = vec![0u64; words];

        // Derive the PDA address
        let pid = Address::from(program_id_bytes);
        let pda_result = Address::create_program_address(
            &[TOKEN_STATE_SEED, &[bump]],
            &pid,
        );

        let pda_addr = match pda_result {
            Ok(addr) => addr,
            Err(_) => {
                // If this bump doesn't produce a valid PDA, use a dummy
                Address::from([0xAA; 32])
            }
        };

        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = 0;
            (*raw).is_writable = 0;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = pda_addr;
            (*raw).owner = Address::from(program_id_bytes);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = TOKEN_STATE_SIZE as u64;
        }

        // Get mutable slice to the data portion
        let data_ptr = unsafe {
            let base = buf.as_mut_ptr() as *mut u8;
            core::slice::from_raw_parts_mut(base.add(header_size), TOKEN_STATE_SIZE)
        };

        // Initialize token_state fields via TokenStateMut
        let mut state = TokenStateMut::from_slice(data_ptr);
        state.set_discriminator(&TOKEN_STATE_DISCRIMINATOR);
        state.set_transfer_authority(&transfer_auth);
        state.set_mint(&mint_addr);
        state.set_pool_ata(&pool_ata_addr);
        state.set_bump(bump);
        state.set_initialized(initialized);
        state.set_paused(paused);

        buf
    }

    // ── Helper: find a valid bump for token_state PDA ───────────────────

    fn find_token_state_bump(program_id_bytes: [u8; 32]) -> u8 {
        let pid = Address::from(program_id_bytes);
        let (_pda, bump) = Address::find_program_address(&[TOKEN_STATE_SEED], &pid);
        bump
    }

    // ── validate_transfer_common tests ──────────────────────────────────

    #[test]
    fn test_validate_transfer_common_wrong_token_state_owner() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        // token_state owned by WRONG program
        let wrong_owner = [99u8; 32];
        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        // Override owner to wrong value
        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).owner = Address::from(wrong_owner); }
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_transfer_common_short_data_len() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);

        // token_state with too-short data
        let header_size = size_of::<RuntimeAccount>();
        let short_data_len = TOKEN_STATE_SIZE - 1;
        let total_bytes = header_size + short_data_len;
        let words = (total_bytes + 7) / 8;
        let mut ts_buf = vec![0u64; words];

        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = 0;
            (*raw).is_writable = 0;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = Address::from([0xBB; 32]);
            (*raw).owner = Address::from(pid_bytes);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = short_data_len as u64;
        }

        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf([3u8; 32], [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf([8u8; 32], TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_validate_transfer_common_not_initialized() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump,
            false, // NOT initialized
            false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::NotInitialized as u32));
    }

    #[test]
    fn test_validate_transfer_common_paused() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump,
            true,
            true, // PAUSED
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::SystemPaused as u32));
    }

    #[test]
    fn test_validate_transfer_common_wrong_authority() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let wrong_auth = [99u8; 32]; // different key
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        // Signer has WRONG address
        let mut auth_buf = make_account_buf(wrong_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_transfer_common_authority_not_signer() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        // Correct address but NOT a signer
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], false, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_transfer_common_wrong_mint_owner() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint owned by WRONG program
        let wrong_program = [77u8; 32];
        let mut mint_buf = make_account_buf(mint_addr, wrong_program, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_transfer_common_wrong_mint_address() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];
        let wrong_mint = [88u8; 32]; // different mint address

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint has WRONG address (different from token_state.mint)
        let mut mint_buf = make_account_buf(wrong_mint, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_transfer_common_wrong_token_program() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        // WRONG token program
        let wrong_tp = [66u8; 32];
        let mut tp_buf = make_account_buf(wrong_tp, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidTokenProgram as u32));
    }

    #[test]
    fn test_validate_transfer_common_happy_path() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().bump, bump);
    }

    #[test]
    fn test_validate_transfer_common_bad_pda() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );

        // Override address to a WRONG value (not the PDA)
        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).address = Address::from([0xCC; 32]); }

        let token_state_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_transfer_common(&pid, &token_state_view, &auth_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidPDA as u32));
    }

    // ── Helper: build a Token-2022 account with inline SPL data ──────────

    /// Build a fake Token-2022 account with mint, owner, and balance inline.
    /// SPL Token-2022 layout: mint (32B) + owner (32B) + amount (8B) + ...
    fn make_token_2022_account_buf(
        address: [u8; 32],
        mint: [u8; 32],
        token_owner: [u8; 32],
        amount: u64,
    ) -> Vec<u64> {
        let header_size = size_of::<RuntimeAccount>();
        let data_len = 165; // SPL Token account minimum size
        let total_bytes = header_size + data_len;
        let words = (total_bytes + 7) / 8;
        let mut buf = vec![0u64; words];

        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = 0;
            (*raw).is_writable = 0;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = Address::from(address);
            (*raw).owner = Address::from(TOKEN_2022_PROGRAM_ID);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = data_len as u64;
        }

        // Write SPL Token account data inline after RuntimeAccount header
        let data_ptr = unsafe {
            let base = buf.as_mut_ptr() as *mut u8;
            core::slice::from_raw_parts_mut(base.add(header_size), data_len)
        };

        data_ptr[0..32].copy_from_slice(&mint);
        data_ptr[32..64].copy_from_slice(&token_owner);
        data_ptr[64..72].copy_from_slice(&amount.to_le_bytes());

        buf
    }

    // ── read_token_balance tests ─────────────────────────────────────────

    #[test]
    fn test_read_token_balance_returns_correct_value() {
        let amount = 42_000_000u64;
        let mut buf = make_token_2022_account_buf([10u8; 32], [1u8; 32], [2u8; 32], amount);
        let view = view_from_buf(&mut buf);
        assert_eq!(read_token_balance(&view), amount);
    }

    #[test]
    fn test_read_token_balance_zero() {
        let mut buf = make_token_2022_account_buf([10u8; 32], [1u8; 32], [2u8; 32], 0);
        let view = view_from_buf(&mut buf);
        assert_eq!(read_token_balance(&view), 0);
    }

    #[test]
    fn test_read_token_balance_max() {
        let mut buf = make_token_2022_account_buf([10u8; 32], [1u8; 32], [2u8; 32], u64::MAX);
        let view = view_from_buf(&mut buf);
        assert_eq!(read_token_balance(&view), u64::MAX);
    }

    // ── read_token_owner tests ───────────────────────────────────────────

    #[test]
    fn test_read_token_owner_returns_correct_pubkey() {
        let token_owner = [7u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], [1u8; 32], token_owner, 100);
        let view = view_from_buf(&mut buf);
        assert_eq!(read_token_owner(&view), &token_owner);
    }

    // ── read_token_mint tests ────────────────────────────────────────────

    #[test]
    fn test_read_token_mint_returns_correct_pubkey() {
        let mint = [9u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, [2u8; 32], 100);
        let view = view_from_buf(&mut buf);
        assert_eq!(read_token_mint(&view), &mint);
    }

    // ── validate_source_ata tests ────────────────────────────────────────

    #[test]
    fn test_validate_source_ata_happy_path() {
        let mint = [5u8; 32];
        let pda_owner = [6u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, pda_owner, 1_000);
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from(mint);
        let owner_addr = Address::from(pda_owner);
        assert!(validate_source_ata(&view, &mint_addr, &owner_addr).is_ok());
    }

    #[test]
    fn test_validate_source_ata_wrong_program_owner() {
        let mint = [5u8; 32];
        let pda_owner = [6u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, pda_owner, 1_000);
        // Override account owner to wrong program
        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).owner = Address::from([99u8; 32]); }
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from(mint);
        let owner_addr = Address::from(pda_owner);
        let result = validate_source_ata(&view, &mint_addr, &owner_addr);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_source_ata_wrong_mint() {
        let mint = [5u8; 32];
        let pda_owner = [6u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, pda_owner, 1_000);
        let view = view_from_buf(&mut buf);
        let wrong_mint = Address::from([88u8; 32]);
        let owner_addr = Address::from(pda_owner);
        let result = validate_source_ata(&view, &wrong_mint, &owner_addr);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_source_ata_wrong_token_owner() {
        let mint = [5u8; 32];
        let pda_owner = [6u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, pda_owner, 1_000);
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from(mint);
        let wrong_owner = Address::from([77u8; 32]);
        let result = validate_source_ata(&view, &mint_addr, &wrong_owner);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    // ── validate_token_state_base tests ──────────────────────────────────

    #[test]
    fn test_validate_token_state_base_happy_path() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);

        let mut ts_buf = make_token_state_account(
            pid_bytes, [3u8; 32], [8u8; 32], [4u8; 32], bump, true, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let result = validate_token_state_base(&pid, &token_state_view);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), bump);
    }

    #[test]
    fn test_validate_token_state_base_wrong_owner() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);

        let mut ts_buf = make_token_state_account(
            pid_bytes, [3u8; 32], [8u8; 32], [4u8; 32], bump, true, false,
        );
        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).owner = Address::from([99u8; 32]); }
        let token_state_view = view_from_buf(&mut ts_buf);

        let result = validate_token_state_base(&pid, &token_state_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_token_state_base_short_data() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);

        let header_size = size_of::<RuntimeAccount>();
        let short_data_len = TOKEN_STATE_SIZE - 1;
        let total_bytes = header_size + short_data_len;
        let words = (total_bytes + 7) / 8;
        let mut ts_buf = vec![0u64; words];

        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = 0;
            (*raw).is_writable = 0;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = Address::from([0xBB; 32]);
            (*raw).owner = Address::from(pid_bytes);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = short_data_len as u64;
        }

        let token_state_view = view_from_buf(&mut ts_buf);
        let result = validate_token_state_base(&pid, &token_state_view);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_validate_token_state_base_bad_pda() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);

        let mut ts_buf = make_token_state_account(
            pid_bytes, [3u8; 32], [8u8; 32], [4u8; 32], bump, true, false,
        );
        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).address = Address::from([0xCC; 32]); }
        let token_state_view = view_from_buf(&mut ts_buf);

        let result = validate_token_state_base(&pid, &token_state_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidPDA as u32));
    }

    #[test]
    fn test_validate_token_state_base_not_initialized() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);

        let mut ts_buf = make_token_state_account(
            pid_bytes, [3u8; 32], [8u8; 32], [4u8; 32], bump, false, false,
        );
        let token_state_view = view_from_buf(&mut ts_buf);

        let result = validate_token_state_base(&pid, &token_state_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::NotInitialized as u32));
    }

    // ── validate_destination_ata_if_exists tests ─────────────────────────

    #[test]
    fn test_validate_dest_ata_empty_account_passes() {
        // Account with data_len=0 should pass (will be created via CPI)
        let (mut buf, _data) = make_account_buf([10u8; 32], [0u8; 32], false, false, 0);
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from([5u8; 32]);
        assert!(validate_destination_ata_if_exists(&view, &mint_addr).is_ok());
    }

    #[test]
    fn test_validate_dest_ata_existing_happy_path() {
        let mint = [5u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, [6u8; 32], 1_000);
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from(mint);
        assert!(validate_destination_ata_if_exists(&view, &mint_addr).is_ok());
    }

    #[test]
    fn test_validate_dest_ata_wrong_program_owner() {
        let mint = [5u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, [6u8; 32], 1_000);
        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).owner = Address::from([99u8; 32]); }
        let view = view_from_buf(&mut buf);
        let mint_addr = Address::from(mint);
        let result = validate_destination_ata_if_exists(&view, &mint_addr);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_dest_ata_wrong_mint() {
        let mint = [5u8; 32];
        let mut buf = make_token_2022_account_buf([10u8; 32], mint, [6u8; 32], 1_000);
        let view = view_from_buf(&mut buf);
        let wrong_mint = Address::from([88u8; 32]);
        let result = validate_destination_ata_if_exists(&view, &wrong_mint);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    // ── Extended helper: token_state with treasury + mint_authority ──────

    /// Build a token_state account with all authority fields set.
    fn make_full_token_state_account(
        program_id_bytes: [u8; 32],
        treasury: [u8; 32],
        mint_auth: [u8; 32],
        transfer_auth: [u8; 32],
        mint_addr: [u8; 32],
        bump: u8,
        initialized: bool,
    ) -> Vec<u64> {
        let header_size = size_of::<RuntimeAccount>();
        let total_bytes = header_size + TOKEN_STATE_SIZE;
        let words = (total_bytes + 7) / 8;
        let mut buf = vec![0u64; words];

        let pid = Address::from(program_id_bytes);
        let pda_addr = Address::create_program_address(
            &[TOKEN_STATE_SEED, &[bump]], &pid,
        ).unwrap_or(Address::from([0xAA; 32]));

        let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe {
            (*raw).borrow_state = NOT_BORROWED;
            (*raw).is_signer = 0;
            (*raw).is_writable = 0;
            (*raw).executable = 0;
            (*raw).resize_delta = 0;
            (*raw).address = pda_addr;
            (*raw).owner = Address::from(program_id_bytes);
            (*raw).lamports = 1_000_000;
            (*raw).data_len = TOKEN_STATE_SIZE as u64;
        }

        let data_ptr = unsafe {
            let base = buf.as_mut_ptr() as *mut u8;
            core::slice::from_raw_parts_mut(base.add(header_size), TOKEN_STATE_SIZE)
        };

        let mut state = TokenStateMut::from_slice(data_ptr);
        state.set_discriminator(&TOKEN_STATE_DISCRIMINATOR);
        state.set_treasury(&treasury);
        state.set_mint_authority(&mint_auth);
        state.set_transfer_authority(&transfer_auth);
        state.set_mint(&mint_addr);
        state.set_pool_ata(&[4u8; 32]);
        state.set_bump(bump);
        state.set_initialized(initialized);
        state.set_paused(false);

        buf
    }

    // ── validate_metadata_accounts tests ─────────────────────────────────

    #[test]
    fn test_validate_metadata_accounts_happy_path() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), bump);
    }

    #[test]
    fn test_validate_metadata_accounts_authority_not_signer() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        // NOT a signer
        let mut auth_buf = make_account_buf(treasury, [0u8; 32], false, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_metadata_accounts_wrong_treasury() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let wrong_treasury = [99u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        // Signer but WRONG treasury address
        let mut auth_buf = make_account_buf(wrong_treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::UnauthorizedTreasury as u32));
    }

    #[test]
    fn test_validate_metadata_accounts_wrong_mint_owner() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint owned by WRONG program
        let mut mint_buf = make_account_buf(mint_addr, [77u8; 32], false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_metadata_accounts_wrong_mint_address() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];
        let wrong_mint = [88u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint has wrong ADDRESS (different from token_state.mint)
        let mut mint_buf = make_account_buf(wrong_mint, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_metadata_accounts_wrong_token_program() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        // WRONG token program
        let mut tp_buf = make_account_buf([66u8; 32], [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidTokenProgram as u32));
    }

    #[test]
    fn test_validate_metadata_accounts_not_initialized() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let treasury = [11u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, treasury, [12u8; 32], [3u8; 32], mint_addr, bump, false, // NOT initialized
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(treasury, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);

        let result = validate_metadata_accounts(&pid, &auth_view, &ts_view, &mint_view, &tp_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::NotInitialized as u32));
    }

    // ── validate_nft_payer tests ─────────────────────────────────────────

    #[test]
    fn test_validate_nft_payer_happy_path() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let mint_auth = [12u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, [11u8; 32], mint_auth, [3u8; 32], [8u8; 32], bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut payer_buf = make_account_buf(mint_auth, [0u8; 32], true, false, 0).0;
        let payer_view = view_from_buf(&mut payer_buf);

        assert!(validate_nft_payer(&pid, &payer_view, &ts_view).is_ok());
    }

    #[test]
    fn test_validate_nft_payer_not_signer() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let mint_auth = [12u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, [11u8; 32], mint_auth, [3u8; 32], [8u8; 32], bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        // NOT a signer
        let mut payer_buf = make_account_buf(mint_auth, [0u8; 32], false, false, 0).0;
        let payer_view = view_from_buf(&mut payer_buf);

        let result = validate_nft_payer(&pid, &payer_view, &ts_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_nft_payer_wrong_mint_authority() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let mint_auth = [12u8; 32];
        let wrong_payer = [99u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, [11u8; 32], mint_auth, [3u8; 32], [8u8; 32], bump, true,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        // Signer but WRONG address (not mint_authority)
        let mut payer_buf = make_account_buf(wrong_payer, [0u8; 32], true, false, 0).0;
        let payer_view = view_from_buf(&mut payer_buf);

        let result = validate_nft_payer(&pid, &payer_view, &ts_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_nft_payer_not_initialized() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let mint_auth = [12u8; 32];

        let mut ts_buf = make_full_token_state_account(
            pid_bytes, [11u8; 32], mint_auth, [3u8; 32], [8u8; 32], bump, false, // NOT initialized
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut payer_buf = make_account_buf(mint_auth, [0u8; 32], true, false, 0).0;
        let payer_view = view_from_buf(&mut payer_buf);

        let result = validate_nft_payer(&pid, &payer_view, &ts_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::NotInitialized as u32));
    }

    // ── execute_pda_transfer tests ──────────────────────────────────────

    #[test]
    fn test_execute_pda_transfer_zero_amount() {
        let pid = Address::from(PROGRAM_ID);
        let d = [1u8; 32];
        let mut b0 = make_account_buf(d, d, true, false, 0).0;
        let mut b1 = make_account_buf(d, d, false, false, 0).0;
        let mut b2 = make_account_buf(d, d, false, false, 0).0;
        let mut b3 = make_account_buf(d, d, false, false, 0).0;
        let mut b4 = make_account_buf(d, d, false, false, 0).0;
        let mut b5 = make_account_buf(d, d, false, false, 0).0;
        let mut b6 = make_account_buf(d, d, false, false, 0).0;
        let mut b7 = make_account_buf(d, d, false, false, 0).0;
        let mut b8 = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &view_from_buf(&mut b0), &view_from_buf(&mut b1),
            &view_from_buf(&mut b2), &view_from_buf(&mut b3),
            &view_from_buf(&mut b4), &view_from_buf(&mut b5),
            &view_from_buf(&mut b6),
            USER_SEED, &1u64.to_le_bytes(), 255,
            &view_from_buf(&mut b7), &view_from_buf(&mut b8),
            COMPANY_SEED, &2u64.to_le_bytes(), 255,
            0, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::ZeroAmount as u32));
    }

    #[test]
    fn test_execute_pda_transfer_invalid_memo() {
        let pid = Address::from(PROGRAM_ID);
        let d = [1u8; 32];
        let mut b0 = make_account_buf(d, d, true, false, 0).0;
        let mut b1 = make_account_buf(d, d, false, false, 0).0;
        let mut b2 = make_account_buf(d, d, false, false, 0).0;
        let mut b3 = make_account_buf(d, d, false, false, 0).0;
        let mut b4 = make_account_buf(d, d, false, false, 0).0;
        let mut b5 = make_account_buf(d, d, false, false, 0).0;
        let mut b6 = make_account_buf(d, d, false, false, 0).0;
        let mut b7 = make_account_buf(d, d, false, false, 0).0;
        let mut b8 = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &view_from_buf(&mut b0), &view_from_buf(&mut b1),
            &view_from_buf(&mut b2), &view_from_buf(&mut b3),
            &view_from_buf(&mut b4), &view_from_buf(&mut b5),
            &view_from_buf(&mut b6),
            USER_SEED, &1u64.to_le_bytes(), 255,
            &view_from_buf(&mut b7), &view_from_buf(&mut b8),
            COMPANY_SEED, &2u64.to_le_bytes(), 255,
            1_000_000, "bad-memo",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMemoFormat as u32));
    }

    #[test]
    fn test_execute_pda_transfer_common_validation_fails() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);

        // token_state with WRONG owner → fails validate_transfer_common
        let mut ts_buf = make_token_state_account(
            pid_bytes, [3u8; 32], [8u8; 32], [4u8; 32], bump, true, false,
        );
        let raw = ts_buf.as_mut_ptr() as *mut RuntimeAccount;
        unsafe { (*raw).owner = Address::from([99u8; 32]); }
        let ts_view = view_from_buf(&mut ts_buf);

        let d = [1u8; 32];
        let mut auth_buf = make_account_buf([3u8; 32], [0u8; 32], true, false, 0).0;
        let mut mint_buf = make_account_buf([8u8; 32], TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let mut sys_buf = make_account_buf(d, d, false, false, 0).0;
        let mut b5 = make_account_buf(d, d, false, false, 0).0;
        let mut b6 = make_account_buf(d, d, false, false, 0).0;
        let mut b7 = make_account_buf(d, d, false, false, 0).0;
        let mut b8 = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &view_from_buf(&mut auth_buf), &ts_view,
            &view_from_buf(&mut mint_buf), &view_from_buf(&mut tp_buf),
            &view_from_buf(&mut sys_buf), &view_from_buf(&mut b5),
            &view_from_buf(&mut b6),
            USER_SEED, &1u64.to_le_bytes(), 255,
            &view_from_buf(&mut b7), &view_from_buf(&mut b8),
            COMPANY_SEED, &2u64.to_le_bytes(), 255,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_execute_pda_transfer_bad_source_pda() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);
        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);
        let mut sys_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        let sys_view = view_from_buf(&mut sys_buf);

        // Source PDA with WRONG address
        let source_id: u64 = 1;
        let source_id_bytes = source_id.to_le_bytes();
        let (_, source_bump) = Address::find_program_address(&[USER_SEED, &source_id_bytes], &pid);
        let mut src_pda_buf = make_account_buf([0xCC; 32], [0u8; 32], false, false, 0).0;
        let src_pda_view = view_from_buf(&mut src_pda_buf);

        let d = [1u8; 32];
        let mut src_ata_buf = make_account_buf(d, d, false, false, 0).0;
        let mut dst_pda_buf = make_account_buf(d, d, false, false, 0).0;
        let mut dst_ata_buf = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &auth_view, &ts_view, &mint_view, &tp_view, &sys_view,
            &src_pda_view, &view_from_buf(&mut src_ata_buf),
            USER_SEED, &source_id_bytes, source_bump,
            &view_from_buf(&mut dst_pda_buf), &view_from_buf(&mut dst_ata_buf),
            COMPANY_SEED, &2u64.to_le_bytes(), 255,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidPDA as u32));
    }

    #[test]
    fn test_execute_pda_transfer_bad_dest_pda() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);
        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);
        let mut sys_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        let sys_view = view_from_buf(&mut sys_buf);

        // VALID source PDA
        let source_id: u64 = 1;
        let source_id_bytes = source_id.to_le_bytes();
        let (src_pda_addr, source_bump) = Address::find_program_address(&[USER_SEED, &source_id_bytes], &pid);
        let mut src_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(src_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = src_pda_addr; }
        let src_pda_view = view_from_buf(&mut src_pda_buf);

        // Dest PDA with WRONG address
        let dest_id: u64 = 2;
        let dest_id_bytes = dest_id.to_le_bytes();
        let (_, dest_bump) = Address::find_program_address(&[COMPANY_SEED, &dest_id_bytes], &pid);
        let mut dst_pda_buf = make_account_buf([0xDD; 32], [0u8; 32], false, false, 0).0;
        let dst_pda_view = view_from_buf(&mut dst_pda_buf);

        let d = [1u8; 32];
        let mut src_ata_buf = make_account_buf(d, d, false, false, 0).0;
        let mut dst_ata_buf = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &auth_view, &ts_view, &mint_view, &tp_view, &sys_view,
            &src_pda_view, &view_from_buf(&mut src_ata_buf),
            USER_SEED, &source_id_bytes, source_bump,
            &dst_pda_view, &view_from_buf(&mut dst_ata_buf),
            COMPANY_SEED, &dest_id_bytes, dest_bump,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidPDA as u32));
    }

    #[test]
    fn test_execute_pda_transfer_bad_source_ata_mint() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);
        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);
        let mut sys_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        let sys_view = view_from_buf(&mut sys_buf);

        // Valid source + dest PDAs
        let source_id: u64 = 1;
        let source_id_bytes = source_id.to_le_bytes();
        let (src_pda_addr, source_bump) = Address::find_program_address(&[USER_SEED, &source_id_bytes], &pid);
        let mut src_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(src_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = src_pda_addr; }
        let src_pda_view = view_from_buf(&mut src_pda_buf);

        let dest_id: u64 = 2;
        let dest_id_bytes = dest_id.to_le_bytes();
        let (dst_pda_addr, dest_bump) = Address::find_program_address(&[COMPANY_SEED, &dest_id_bytes], &pid);
        let mut dst_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(dst_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = dst_pda_addr; }
        let dst_pda_view = view_from_buf(&mut dst_pda_buf);

        // Source ATA with WRONG mint → InvalidMint
        let mut src_ata_buf = make_token_2022_account_buf(
            [20u8; 32], [99u8; 32], [0u8; 32], 1_000_000,
        );
        let src_ata_view = view_from_buf(&mut src_ata_buf);

        let d = [1u8; 32];
        let mut dst_ata_buf = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &auth_view, &ts_view, &mint_view, &tp_view, &sys_view,
            &src_pda_view, &src_ata_view,
            USER_SEED, &source_id_bytes, source_bump,
            &dst_pda_view, &view_from_buf(&mut dst_ata_buf),
            COMPANY_SEED, &dest_id_bytes, dest_bump,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_execute_pda_transfer_insufficient_balance() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);
        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);
        let mut sys_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        let sys_view = view_from_buf(&mut sys_buf);

        // Valid source + dest PDAs
        let source_id: u64 = 1;
        let source_id_bytes = source_id.to_le_bytes();
        let (src_pda_addr, source_bump) = Address::find_program_address(&[USER_SEED, &source_id_bytes], &pid);
        let mut src_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(src_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = src_pda_addr; }
        let src_pda_view = view_from_buf(&mut src_pda_buf);

        let dest_id: u64 = 2;
        let dest_id_bytes = dest_id.to_le_bytes();
        let (dst_pda_addr, dest_bump) = Address::find_program_address(&[COMPANY_SEED, &dest_id_bytes], &pid);
        let mut dst_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(dst_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = dst_pda_addr; }
        let dst_pda_view = view_from_buf(&mut dst_pda_buf);

        // Source ATA: valid mint + owner, but LOW balance
        let mut src_pda_bytes = [0u8; 32];
        src_pda_bytes.copy_from_slice(src_pda_addr.as_ref());
        let mut src_ata_buf = make_token_2022_account_buf(
            [20u8; 32], mint_addr, src_pda_bytes, 500,
        );
        let src_ata_view = view_from_buf(&mut src_ata_buf);

        let d = [1u8; 32];
        let mut dst_ata_buf = make_account_buf(d, d, false, false, 0).0;

        let result = execute_pda_transfer(
            &pid,
            &auth_view, &ts_view, &mint_view, &tp_view, &sys_view,
            &src_pda_view, &src_ata_view,
            USER_SEED, &source_id_bytes, source_bump,
            &dst_pda_view, &view_from_buf(&mut dst_ata_buf),
            COMPANY_SEED, &dest_id_bytes, dest_bump,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InsufficientBalance as u32));
    }

    #[test]
    fn test_execute_pda_transfer_bad_dest_ata_mint() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);
        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);
        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);
        let mut tp_buf = make_account_buf(TOKEN_2022_PROGRAM_ID, [0u8; 32], false, false, 0).0;
        let tp_view = view_from_buf(&mut tp_buf);
        let mut sys_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        let sys_view = view_from_buf(&mut sys_buf);

        // Valid source + dest PDAs
        let source_id: u64 = 1;
        let source_id_bytes = source_id.to_le_bytes();
        let (src_pda_addr, source_bump) = Address::find_program_address(&[USER_SEED, &source_id_bytes], &pid);
        let mut src_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(src_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = src_pda_addr; }
        let src_pda_view = view_from_buf(&mut src_pda_buf);

        let dest_id: u64 = 2;
        let dest_id_bytes = dest_id.to_le_bytes();
        let (dst_pda_addr, dest_bump) = Address::find_program_address(&[COMPANY_SEED, &dest_id_bytes], &pid);
        let mut dst_pda_buf = make_account_buf([0u8; 32], [0u8; 32], false, false, 0).0;
        unsafe { (*(dst_pda_buf.as_mut_ptr() as *mut RuntimeAccount)).address = dst_pda_addr; }
        let dst_pda_view = view_from_buf(&mut dst_pda_buf);

        // Source ATA: valid mint + owner + SUFFICIENT balance
        let mut src_pda_bytes = [0u8; 32];
        src_pda_bytes.copy_from_slice(src_pda_addr.as_ref());
        let mut src_ata_buf = make_token_2022_account_buf(
            [20u8; 32], mint_addr, src_pda_bytes, 2_000_000,
        );
        let src_ata_view = view_from_buf(&mut src_ata_buf);

        // Dest ATA: exists (data_len > 0) with WRONG mint → InvalidMint
        let mut dst_ata_buf = make_token_2022_account_buf(
            [30u8; 32], [88u8; 32], [0u8; 32], 0,
        );
        let dst_ata_view = view_from_buf(&mut dst_ata_buf);

        let result = execute_pda_transfer(
            &pid,
            &auth_view, &ts_view, &mint_view, &tp_view, &sys_view,
            &src_pda_view, &src_ata_view,
            USER_SEED, &source_id_bytes, source_bump,
            &dst_pda_view, &dst_ata_view,
            COMPANY_SEED, &dest_id_bytes, dest_bump,
            1_000_000, "zupy:v1:transfer:123",
        );
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    // ── validate_transfer_common_compressed ──────────────────────────────

    #[test]
    fn test_validate_transfer_common_compressed_happy_path() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert!(result.is_ok(), "happy path must succeed");
        assert_eq!(result.unwrap().bump, bump);
    }

    #[test]
    fn test_validate_transfer_common_compressed_paused_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, true, // paused=true
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::SystemPaused as u32));
    }

    #[test]
    fn test_validate_transfer_common_compressed_authority_not_signer_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], false, false, 0).0; // not signer
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_transfer_common_compressed_wrong_authority_address_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let wrong_auth = [0xBBu8; 32]; // different address
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(wrong_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidAuthority as u32));
    }

    #[test]
    fn test_validate_transfer_common_compressed_wrong_mint_owner_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint owned by wrong program (not Token-2022)
        let mut mint_buf = make_account_buf(mint_addr, [0xAAu8; 32], false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_transfer_common_compressed_wrong_mint_address_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];
        let wrong_mint = [0xCCu8; 32]; // different address

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, true, false,
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        // Mint account address doesn't match token_state.mint
        let mut mint_buf = make_account_buf(wrong_mint, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::InvalidMint as u32));
    }

    #[test]
    fn test_validate_transfer_common_compressed_not_initialized_returns_error() {
        let pid_bytes = PROGRAM_ID;
        let pid = Address::from(pid_bytes);
        let bump = find_token_state_bump(pid_bytes);
        let transfer_auth = [3u8; 32];
        let mint_addr = [8u8; 32];

        let mut ts_buf = make_token_state_account(
            pid_bytes, transfer_auth, mint_addr, [4u8; 32], bump, false, false, // initialized=false
        );
        let ts_view = view_from_buf(&mut ts_buf);

        let mut auth_buf = make_account_buf(transfer_auth, [0u8; 32], true, false, 0).0;
        let auth_view = view_from_buf(&mut auth_buf);

        let mut mint_buf = make_account_buf(mint_addr, TOKEN_2022_PROGRAM_ID, false, false, 0).0;
        let mint_view = view_from_buf(&mut mint_buf);

        let result = validate_transfer_common_compressed(&pid, &ts_view, &auth_view, &mint_view);
        assert_eq!(result.unwrap_err(), ProgramError::Custom(ZupyTokenError::NotInitialized as u32));
    }
}
