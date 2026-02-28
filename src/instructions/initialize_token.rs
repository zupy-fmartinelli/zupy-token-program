use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{
    DAILY_AUTO_LIMIT, PER_TX_AUTO_LIMIT, TOKEN_2022_PROGRAM_ID, TOKEN_DECIMALS, TOKEN_STATE_SEED,
};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::{cpi_create_account, cpi_initialize_metadata_pointer, cpi_initialize_mint};
use crate::helpers::instruction_data::parse_pubkey;
use crate::helpers::pda::{
    derive_distribution_pool_pda, derive_incentive_pool_pda, derive_token_state_pda, validate_pda,
};
use crate::state::token_state::{TokenStateMut, TOKEN_STATE_DISCRIMINATOR, TOKEN_STATE_SIZE};

/// Mint size for Token-2022 with MetadataPointer extension.
/// Token-2022 pads base mint to BASE_ACCOUNT_LENGTH (165) before TLV extensions:
/// 165 (padded base) + 1 (AccountType) + 2 (ext type LE) + 2 (ext length LE) + 64 (MetadataPointer) = 234
const MINT_WITH_METADATA_POINTER_SIZE: u64 = 234;

/// Process `initialize_token` instruction.
///
/// One-time program setup: creates TokenState PDA + Token-2022 mint with MetadataPointer.
///
/// Accounts (8):
///   0. authority (writable, signer) — payer
///   1. token_state (writable) — PDA [TOKEN_STATE_SEED], init 363 bytes
///   2. mint (writable, signer) — fresh keypair, Token-2022 mint
///   3. pool_ata (writable) — stored in state
///   4. treasury_ata (writable) — stored in state
///   5. system_program (read)
///   6. token_program (read) — Token-2022
///   7. associated_token_program (read)
///
/// Data: treasury (pubkey) + mint_authority (pubkey) + transfer_authority (pubkey)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (8 accounts) ─────────────────────────────────
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let token_state_account = &accounts[1];
    let mint = &accounts[2];
    let pool_ata = &accounts[3];
    let treasury_ata = &accounts[4];
    let _system_program = &accounts[5];
    let token_program = &accounts[6];
    let _associated_token_program = &accounts[7];

    // ── Parse instruction data: 3 pubkeys ───────────────────────────────
    let (treasury_pubkey, offset) = parse_pubkey(data, 0)?;
    let (mint_authority_pubkey, offset) = parse_pubkey(data, offset)?;
    let (transfer_authority_pubkey, _) = parse_pubkey(data, offset)?;

    // ── Signer checks ──────────────────────────────────────────────────
    if !authority.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }
    if !mint.is_signer() {
        return Err(ZupyTokenError::InvalidAuthority.into());
    }

    // ── Token program check ─────────────────────────────────────────────
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── PDA validation: token_state ─────────────────────────────────────
    let (expected_pda, bump) = derive_token_state_pda(program_id);
    validate_pda(token_state_account.address(), &expected_pda)?;

    // ── Init guard: account must not already exist ──────────────────────
    if token_state_account.data_len() > 0 {
        return Err(ZupyTokenError::AlreadyInitialized.into());
    }

    // ── Derive pool PDAs for storage ────────────────────────────────────
    let (distribution_pool_pda, _) = derive_distribution_pool_pda(program_id);
    let (incentive_pool_pda, _) = derive_incentive_pool_pda(program_id);

    // ── CPI 1: Create TokenState PDA account (363 bytes) ────────────────
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 2] = [
        Seed::from(TOKEN_STATE_SEED),
        Seed::from(bump_bytes.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    cpi_create_account(
        authority,
        token_state_account,
        TOKEN_STATE_SIZE as u64,
        program_id,
        &[signer],
    )?;

    // ── CPI 2: Create mint account (151 bytes for MetadataPointer) ──────
    cpi_create_account(
        authority,
        mint,
        MINT_WITH_METADATA_POINTER_SIZE,
        &token_2022_addr,
        &[], // mint signs as keypair, not PDA
    )?;

    // ── CPI 3: Initialize MetadataPointer extension (BEFORE InitializeMint)
    cpi_initialize_metadata_pointer(
        mint,
        &expected_pda, // authority = token_state PDA
        token_program,
    )?;

    // ── CPI 4: Initialize Mint (decimals=6, authority=token_state PDA) ──
    cpi_initialize_mint(
        mint,
        &expected_pda,         // mint_authority = token_state PDA
        Some(&expected_pda),   // freeze_authority = token_state PDA
        TOKEN_DECIMALS,
        &token_2022_addr,
    )?;

    // ── Populate TokenState fields ──────────────────────────────────────
    let mut state =
        TokenStateMut::from_slice(unsafe { token_state_account.borrow_unchecked_mut() });

    state.set_discriminator(&TOKEN_STATE_DISCRIMINATOR);
    state.set_treasury(treasury_pubkey);
    state.set_mint_authority(mint_authority_pubkey);
    state.set_transfer_authority(transfer_authority_pubkey);

    // Pool/treasury ATAs stored unchecked per spec — validated at use-time by hot-path instructions
    let pool_ata_key: &[u8; 32] = pool_ata.address().as_ref().try_into().unwrap();
    state.set_pool_ata(pool_ata_key);

    let dist_key: &[u8; 32] = distribution_pool_pda.as_ref().try_into().unwrap();
    state.set_distribution_pool(dist_key);

    let incentive_key: &[u8; 32] = incentive_pool_pda.as_ref().try_into().unwrap();
    state.set_incentive_pool(incentive_key);

    let treasury_ata_key: &[u8; 32] = treasury_ata.address().as_ref().try_into().unwrap();
    state.set_treasury_ata(treasury_ata_key);

    let mint_key: &[u8; 32] = mint.address().as_ref().try_into().unwrap();
    state.set_mint(mint_key);

    state.set_initialized(true);
    state.set_bump(bump);
    state.set_per_tx_auto_limit(PER_TX_AUTO_LIMIT);
    state.set_daily_auto_limit(DAILY_AUTO_LIMIT);
    state.set_daily_minted(0);
    state.set_last_reset_timestamp(0);
    state.set_paused(false);

    Ok(())
}
