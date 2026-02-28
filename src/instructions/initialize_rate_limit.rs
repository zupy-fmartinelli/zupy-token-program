use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{RATE_LIMIT_SEED, SECONDS_PER_DAY};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_create_account;
use crate::helpers::pda::{derive_rate_limit_pda, validate_pda};
use crate::state::rate_limit_state::{
    RateLimitStateMut, RATE_LIMIT_STATE_DISCRIMINATOR, RATE_LIMIT_STATE_SIZE,
};

/// Process `initialize_rate_limit` instruction.
///
/// Creates a per-authority RateLimitState PDA account (57 bytes).
/// No instruction data beyond discriminator.
///
/// Accounts (3):
///   0. authority (writable, signer) — payer
///   1. rate_limit_state (writable) — PDA [RATE_LIMIT_SEED, authority.key()]
///   2. system_program (read)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    _data: &[u8],
) -> ProgramResult {
    // ── Account extraction (3 accounts) ─────────────────────────────────
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let rate_limit_state = &accounts[1];
    let _system_program = &accounts[2];

    // ── Signer check ────────────────────────────────────────────────────
    if !authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── PDA validation ──────────────────────────────────────────────────
    let auth_key: &[u8; 32] = authority.address().as_ref().try_into().unwrap();
    let (expected_pda, bump) = derive_rate_limit_pda(program_id, auth_key);
    validate_pda(rate_limit_state.address(), &expected_pda)?;

    // ── Init guard: account must not already exist ──────────────────────
    if rate_limit_state.data_len() > 0 {
        return Err(ZupyTokenError::AlreadyInitialized.into());
    }

    // ── CPI: Create account (57 bytes) ──────────────────────────────────
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 3] = [
        Seed::from(RATE_LIMIT_SEED),
        Seed::from(auth_key.as_ref()),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_create_account(
        authority,
        rate_limit_state,
        RATE_LIMIT_STATE_SIZE as u64,
        program_id,
        &[signer],
    )?;

    // ── Timestamp: current_day = unix_timestamp / SECONDS_PER_DAY ───────
    use pinocchio::sysvars::Sysvar as _;
    let clock = pinocchio::sysvars::clock::Clock::get()?;
    let current_day = (clock.unix_timestamp / SECONDS_PER_DAY) as u64;

    // ── Initialize state fields ─────────────────────────────────────────
    let mut state =
        RateLimitStateMut::from_slice(unsafe { rate_limit_state.borrow_unchecked_mut() });
    state.set_discriminator(&RATE_LIMIT_STATE_DISCRIMINATOR);
    state.set_authority(auth_key);
    state.set_current_day(current_day);
    state.set_minted_today(0);
    state.set_bump(bump);

    Ok(())
}
