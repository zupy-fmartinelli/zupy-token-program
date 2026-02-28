use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::error::ZupyTokenError;
use crate::helpers::instruction_data::parse_bool;
use crate::helpers::transfer_validation::validate_token_state_base;
use crate::state::token_state::{TokenState, TokenStateMut};

/// Process `set_paused` instruction.
///
/// Emergency pause/unpause of the system.
/// Only the treasury wallet can toggle pause state.
///
/// Accounts (2):
///   0. authority (signer) — must be token_state.treasury()
///   1. token_state (writable) — PDA [TOKEN_STATE_SEED]
///
/// Data: paused (bool, 1 byte)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (2 accounts) ─────────────────────────────────
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let token_state_account = &accounts[1];

    // ── Parse instruction data ──────────────────────────────────────────
    let paused = parse_bool(data, 0)?;

    // ── Base token_state validation (§7.1, §7.7, §7.2, §7.4) ──────────
    validate_token_state_base(program_id, token_state_account)?;

    // Zero-copy read for treasury authorization
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // ── Treasury authorization (AC6) ────────────────────────────────────
    if !authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    let authority_key: &[u8; 32] = authority.address().as_ref().try_into().unwrap();
    if !state.is_treasury(authority_key) {
        return Err(ZupyTokenError::UnauthorizedTreasury.into());
    }

    // ── Update paused flag ──────────────────────────────────────────────
    let mut state_mut =
        TokenStateMut::from_slice(unsafe { token_state_account.borrow_unchecked_mut() });
    state_mut.set_paused(paused);

    Ok(())
}
