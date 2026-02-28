use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{BASIC_MINT_SIZE, TOKEN_2022_PROGRAM_ID, ZUPY_CARD_MINT_SEED, ZUPY_CARD_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::{
    cpi_create_account, cpi_create_ata_if_needed, cpi_initialize_mint, cpi_mint_to,
};
use crate::helpers::instruction_data::{parse_bytes, parse_string};
use crate::helpers::pda::{
    derive_user_nft_pda, derive_zupy_card_mint_pda, derive_zupy_card_pda,
    validate_pda,
};
use crate::helpers::transfer_validation::validate_nft_payer;
use crate::state::zupy_card::{ZupyCardMut, ZUPY_CARD_DISCRIMINATOR, ZUPY_CARD_SIZE};

/// Process `create_zupy_card` instruction.
///
/// Creates a soulbound Zuper Card NFT: ZupyCard PDA + mint PDA + ATA + mint 1.
///
/// Accounts (9):
///   0. user_pda (read) — PDA [b"user_pda", &user_ksuid]
///   1. zupy_card (writable) — PDA [b"zupy_card", &user_ksuid], init 108 bytes
///   2. mint (writable) — PDA [b"zupy_card_mint", &user_ksuid], init mint
///   3. token_account (writable) — ATA for user_pda
///   4. token_state (read) — PDA [TOKEN_STATE_SEED], Audit 12.1
///   5. payer (writable, signer) — must match token_state.mint_authority()
///   6. token_program (read) — Token-2022
///   7. associated_token_program (read)
///   8. system_program (read)
///
/// Data: user_ksuid ([u8; 27]) + metadata_uri (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (9 accounts) ─────────────────────────────────
    if accounts.len() < 9 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let user_pda = &accounts[0];
    let zupy_card = &accounts[1];
    let mint = &accounts[2];
    let token_account = &accounts[3];
    let token_state_account = &accounts[4];
    let payer = &accounts[5];
    let token_program = &accounts[6];
    let _associated_token_program = &accounts[7];
    let system_program = &accounts[8];

    // ── Parse instruction data ──────────────────────────────────────────
    let (user_ksuid, offset) = parse_bytes::<27>(data, 0)?;
    let (_metadata_uri, _) = parse_string(data, offset)?;

    // ── NFT payer validation (signer + token_state + mint_authority) ─────
    validate_nft_payer(program_id, payer, token_state_account)?;

    // ── Token program check ─────────────────────────────────────────────
    let token_2022_addr = Address::from(TOKEN_2022_PROGRAM_ID);
    if token_program.address() != &token_2022_addr {
        return Err(ZupyTokenError::InvalidTokenProgram.into());
    }

    // ── PDA validations ─────────────────────────────────────────────────
    let (expected_user_pda, _) = derive_user_nft_pda(program_id, user_ksuid);
    validate_pda(user_pda.address(), &expected_user_pda)?;

    let (expected_card_pda, card_bump) = derive_zupy_card_pda(program_id, user_ksuid);
    validate_pda(zupy_card.address(), &expected_card_pda)?;

    let (expected_mint_pda, mint_bump) = derive_zupy_card_mint_pda(program_id, user_ksuid);
    validate_pda(mint.address(), &expected_mint_pda)?;

    // ── Init guard: zupy_card must not already exist ─────────────────────
    if zupy_card.data_len() > 0 {
        return Err(ZupyTokenError::AlreadyInitialized.into());
    }

    // ── CPI 1: Create ZupyCard PDA (108 bytes) ──────────────────────────
    let card_bump_bytes = [card_bump];
    let card_signer_seeds: [Seed; 3] = [
        Seed::from(ZUPY_CARD_SEED),
        Seed::from(user_ksuid.as_ref()),
        Seed::from(card_bump_bytes.as_ref()),
    ];
    let card_signer = Signer::from(&card_signer_seeds);

    cpi_create_account(
        payer,
        zupy_card,
        ZUPY_CARD_SIZE as u64,
        program_id,
        &[card_signer],
    )?;

    // ── CPI 2: Create mint PDA (82 bytes, owned by Token-2022) ──────────
    let mint_bump_bytes = [mint_bump];
    let mint_signer_seeds: [Seed; 3] = [
        Seed::from(ZUPY_CARD_MINT_SEED),
        Seed::from(user_ksuid.as_ref()),
        Seed::from(mint_bump_bytes.as_ref()),
    ];
    let mint_signer = Signer::from(&mint_signer_seeds);

    cpi_create_account(
        payer,
        mint,
        BASIC_MINT_SIZE,
        &token_2022_addr,
        &[mint_signer],
    )?;

    // ── CPI 3: Initialize mint (decimals=0, authority=zupy_card PDA) ────
    cpi_initialize_mint(
        mint,
        &expected_card_pda,       // mint_authority = zupy_card PDA
        Some(&expected_card_pda), // freeze_authority = zupy_card PDA
        0,                        // decimals = 0 for NFT
        &token_2022_addr,
    )?;

    // ── CPI 4: Create ATA for user_pda ──────────────────────────────────
    cpi_create_ata_if_needed(
        token_account,
        payer,
        user_pda,
        mint,
        token_program,
        system_program,
    )?;

    // ── CPI 5: Mint 1 NFT to the ATA (zupy_card PDA signs) ─────────────
    let card_signer_seeds2: [Seed; 3] = [
        Seed::from(ZUPY_CARD_SEED),
        Seed::from(user_ksuid.as_ref()),
        Seed::from(card_bump_bytes.as_ref()),
    ];
    let card_signer2 = Signer::from(&card_signer_seeds2);

    cpi_mint_to(
        mint,
        token_account,
        zupy_card, // authority = zupy_card PDA
        1,
        &token_2022_addr,
        &[card_signer2],
    )?;

    // ── Populate ZupyCard state ─────────────────────────────────────────
    use pinocchio::sysvars::Sysvar as _;
    let clock = pinocchio::sysvars::clock::Clock::get()?;

    let mut card_state =
        ZupyCardMut::from_slice(unsafe { zupy_card.borrow_unchecked_mut() });
    card_state.set_discriminator(&ZUPY_CARD_DISCRIMINATOR);
    let owner_key: &[u8; 32] = user_pda.address().as_ref().try_into().unwrap();
    card_state.set_owner(owner_key);
    let mint_key: &[u8; 32] = mint.address().as_ref().try_into().unwrap();
    card_state.set_mint(mint_key);
    card_state.set_user_ksuid(user_ksuid);
    card_state.set_created_at(clock.unix_timestamp);
    card_state.set_bump(card_bump);

    Ok(())
}
