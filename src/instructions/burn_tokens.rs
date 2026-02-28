use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::TOKEN_2022_PROGRAM_ID;
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_burn_invoke;
use crate::helpers::instruction_data::{parse_string, parse_u64};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::transfer_validation::{
    read_token_balance, read_token_mint, validate_token_state_base,
};
use crate::state::token_state::TokenState;

/// Process `burn_tokens` instruction.
///
/// Burns tokens from `token_account` via regular invoke (NOT invoke_signed).
/// `token_account_owner` is the signer (holder authorization).
///
/// NOTE: Does NOT check `paused` — treasury can authorize burns even when paused.
///
/// Accounts (6):
///   0. authority (signer) — must be treasury
///   1. token_state (read)
///   2. mint (writable)
///   3. token_account (writable)
///   4. token_account_owner (signer)
///   5. token_program (read)
///
/// Data: amount (u64) + memo (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (6 accounts) ─────────────────────────────────
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let token_account = &accounts[3];
    let token_account_owner = &accounts[4];
    let token_program = &accounts[5];

    // ── Parse instruction data ──────────────────────────────────────────
    let amount = parse_u64(data, 0)?;
    let (memo, _) = parse_string(data, 8)?;

    // ── Input validation ────────────────────────────────────────────────
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;

    // ── Base token_state validation (§7.1, §7.7, §7.2, §7.4) ──────────
    validate_token_state_base(program_id, token_state_account)?;
    // NOTE: burn_tokens does NOT check paused (intentional)

    // Zero-copy read for authority checks
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // ── Signer checks (Spec §7.3) ───────────────────────────────────────
    if !authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    // authority must be treasury
    if state.treasury() != authority.address().as_ref() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    // token_account_owner must be signer (holder authorization)
    if !token_account_owner.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Mint ownership (Spec §7.1) + match ──────────────────────────────
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !mint.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidMint.into());
    }
    if state.mint() != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // ── token_account ownership (Spec §7.1) ─────────────────────────────
    if !token_account.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── token_account mint check ────────────────────────────────────────
    if read_token_mint(token_account) != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // ── CPI safety: token_program is Token-2022 (Spec §7.8) ────────────
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── Balance check ───────────────────────────────────────────────────
    let balance = read_token_balance(token_account);
    if balance < amount {
        return Err(ZupyTokenError::InsufficientBalance.into());
    }

    // ── CPI: Token-2022 Burn via regular invoke ─────────────────────────
    cpi_burn_invoke(
        token_account,
        mint,
        token_account_owner,
        amount,
        token_program.address(),
    )?;

    Ok(())
}
