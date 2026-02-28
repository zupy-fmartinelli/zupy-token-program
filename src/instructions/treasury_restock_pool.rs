use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{TOKEN_2022_PROGRAM_ID, TREASURY_WALLET_PUBKEY};
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
///   4. treasury_wallet (signer) — hardcoded TREASURY_WALLET_PUBKEY
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

    // ── Treasury wallet: hardcoded address + signer ─────────────────────
    // Deliberate: uses UnauthorizedTreasury (not assert_key_eq) for clearer error semantics
    let expected_treasury = Address::from(TREASURY_WALLET_PUBKEY);
    if treasury_wallet.address() != &expected_treasury {
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
