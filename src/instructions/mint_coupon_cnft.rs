use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{BUBBLEGUM_PROGRAM_ID, SPL_ACCOUNT_COMPRESSION_ID, SPL_NOOP_ID};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::cpi_bubblegum_mint_v1;
use crate::helpers::instruction_data::parse_string;
use crate::helpers::transfer_validation::validate_nft_payer;

/// Process `mint_coupon_cnft` instruction.
///
/// Mints a compressed NFT via manual Bubblegum MintV1 CPI (no mpl-bubblegum dependency).
/// tree_authority signs directly (regular invoke).
///
/// Accounts (10):
///   0. tree_authority (writable, signer)
///   1. leaf_owner (read) — NFT recipient
///   2. merkle_tree (writable)
///   3. tree_config (writable)
///   4. payer (writable, signer)
///   5. bubblegum_program (read)
///   6. compression_program (read)
///   7. log_wrapper (read)
///   8. system_program (read)
///   9. token_state (read) — PDA [TOKEN_STATE_SEED], Audit 12.1
///
/// Data: name (String) + symbol (String) + uri (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (10 accounts) ────────────────────────────────
    if accounts.len() < 10 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let tree_authority = &accounts[0];
    let leaf_owner = &accounts[1];
    let merkle_tree = &accounts[2];
    let tree_config = &accounts[3];
    let payer = &accounts[4];
    let bubblegum_program = &accounts[5];
    let compression_program = &accounts[6];
    let log_wrapper = &accounts[7];
    let system_program = &accounts[8];
    let token_state_account = &accounts[9];

    // ── Parse instruction data ──────────────────────────────────────────
    let (name, offset) = parse_string(data, 0)?;
    let (symbol, offset) = parse_string(data, offset)?;
    let (uri, _) = parse_string(data, offset)?;

    // ── Signer check: tree_authority ─────────────────────────────────────
    if !tree_authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── NFT payer validation (signer + token_state + mint_authority) ─────
    validate_nft_payer(program_id, payer, token_state_account)?;

    // ── Hardcoded program ID checks ─────────────────────────────────────
    let expected_bubblegum = Address::from(BUBBLEGUM_PROGRAM_ID);
    if bubblegum_program.address() != &expected_bubblegum {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    let expected_compression = Address::from(SPL_ACCOUNT_COMPRESSION_ID);
    if compression_program.address() != &expected_compression {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    let expected_noop = Address::from(SPL_NOOP_ID);
    if log_wrapper.address() != &expected_noop {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── CPI: Bubblegum MintV1 (regular invoke) ──────────────────────────
    cpi_bubblegum_mint_v1(
        tree_config,
        leaf_owner,
        merkle_tree,
        payer,
        tree_authority,
        log_wrapper,
        compression_program,
        system_program,
        bubblegum_program,
        name,
        symbol,
        uri,
    )?;

    Ok(())
}
