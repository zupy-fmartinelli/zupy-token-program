use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{TOKEN_2022_PROGRAM_ID, TOKEN_STATE_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_mint_to;
use crate::helpers::instruction_data::{parse_string, parse_u64};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::transfer_validation::validate_token_state_base;
use crate::state::token_state::{TokenState, TokenStateMut};

/// Process `mint_tokens` instruction.
///
/// Rate-limited mint to treasury ATA via Token-2022 MintTo CPI.
/// PDA signer: token_state [TOKEN_STATE_SEED, &[bump]].
///
/// Accounts (5):
///   0. mint_authority (writable, signer) — must match token_state.mint_authority()
///   1. token_state (writable) — PDA [TOKEN_STATE_SEED], rate limit updates
///   2. mint (writable) — Token-2022 mint
///   3. treasury_ata (writable) — MintTo destination
///   4. token_program (read) — Token-2022
///
/// Data: amount (u64) + memo (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (5 accounts) ─────────────────────────────────
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mint_authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let treasury_ata = &accounts[3];
    let token_program = &accounts[4];

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

    // Zero-copy read for remaining checks
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

    // ── Paused check ────────────────────────────────────────────────────
    if state.paused() {
        return Err(ZupyTokenError::SystemPaused.into());
    }

    // ── Signer + mint_authority check ───────────────────────────────────
    if !mint_authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    let mint_auth_key: &[u8; 32] = mint_authority.address().as_ref().try_into().unwrap();
    if !state.is_mint_authority(mint_auth_key) {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Mint validation ─────────────────────────────────────────────────
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if !mint.owned_by(&token_2022_addr) {
        return Err(ZupyTokenError::InvalidMint.into());
    }
    if state.mint() != mint.address().as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    // ── Treasury ATA validation ─────────────────────────────────────────
    if state.treasury_ata() != treasury_ata.address().as_ref() {
        return Err(ZupyTokenError::InvalidTreasuryAccount.into());
    }

    // ── Token program check ─────────────────────────────────────────────
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── Rate limits ─────────────────────────────────────────────────────
    use pinocchio::sysvars::Sysvar as _;
    let clock = pinocchio::sysvars::clock::Clock::get()?;

    // Per-transaction limit
    if !state.within_tx_limit(amount) {
        return Err(ZupyTokenError::ExceedsTransactionLimit.into());
    }

    // Daily limit (simulate reset for pre-CPI check — CEI pattern)
    let current_day = clock.unix_timestamp / 86400;
    let last_day = state.last_reset_timestamp() / 86400;
    let effective_daily = if current_day > last_day { 0 } else { state.daily_minted() };
    if effective_daily.saturating_add(amount) > state.daily_auto_limit() {
        return Err(ZupyTokenError::ExceedsDailyLimit.into());
    }

    let bump = state.bump();

    // ── CPI: Token-2022 MintTo ──────────────────────────────────────────
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 2] = [
        Seed::from(TOKEN_STATE_SEED),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_mint_to(
        mint,
        treasury_ata,
        token_state_account,
        amount,
        token_program.address(),
        &[signer],
    )?;

    // ── Record mint AFTER successful CPI ──────────────────────────────
    let mut state_mut =
        TokenStateMut::from_slice(unsafe { token_state_account.borrow_unchecked_mut() });
    state_mut.maybe_reset_daily(clock.unix_timestamp);
    state_mut.record_mint(amount);

    Ok(())
}
