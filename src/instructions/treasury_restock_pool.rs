use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::TOKEN_2022_PROGRAM_ID;
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_transfer;
use crate::helpers::instruction_data::{parse_string, parse_u64};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::transfer_validation::{
    read_token_balance, validate_source_ata, validate_token_state_base,
};
use crate::state::token_state::TokenState;

/// Process `treasury_restock_pool` instruction.
///
/// Transfers tokens from treasury_ata to pool_ata.
/// treasury_wallet signs directly (regular invoke, no invoke_signed).
/// No rate limits — manual Trezor signing IS the security control.
///
/// Accounts (6):
///   0. token_state (read) — PDA [TOKEN_STATE_SEED]
///   1. mint (read) — Token-2022 mint
///   2. treasury_ata (writable) — source
///   3. pool_ata (writable) — destination
///   4. treasury_wallet (signer) — must equal token_state.treasury()
///   5. token_program (read) — Token-2022
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
    let token_state_account = &accounts[0];
    let mint = &accounts[1];
    let treasury_ata = &accounts[2];
    let pool_ata = &accounts[3];
    let treasury_wallet = &accounts[4];
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

    // Zero-copy read for remaining checks
    let state = TokenState::from_slice(unsafe { token_state_account.borrow_unchecked() });

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
    validate_source_ata(treasury_ata, mint.address(), treasury_wallet.address())?;

    // ── Pool ATA validation ─────────────────────────────────────────────
    if state.pool_ata() != pool_ata.address().as_ref() {
        return Err(ZupyTokenError::InvalidPoolAccount.into());
    }

    // ── Treasury wallet: token_state.treasury + signer ──────────────────
    // One source of truth (story 36.2): the same value set_paused and the
    // metadata pair trust. Deliberate: UnauthorizedTreasury for clearer errors.
    // Not gated by the pause: the treasury is the cold key that sets/clears it.
    let treasury_key: &[u8; 32] = treasury_wallet.address().as_ref().try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if !state.is_treasury(treasury_key) {
        return Err(ZupyTokenError::UnauthorizedTreasury.into());
    }
    if !treasury_wallet.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Token program check ─────────────────────────────────────────────
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── Balance check ───────────────────────────────────────────────────
    let balance = read_token_balance(treasury_ata);
    if balance < amount {
        return Err(ZupyTokenError::InsufficientBalance.into());
    }

    // ── CPI: Transfer (regular invoke — treasury_wallet is signer) ──────
    cpi_transfer(
        treasury_ata,
        pool_ata,
        treasury_wallet,
        amount,
        token_program.address(),
        &[], // empty signers = regular invoke
    )?;

    Ok(())
}
