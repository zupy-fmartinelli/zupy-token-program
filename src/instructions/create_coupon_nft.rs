use pinocchio::cpi::{Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::{BASIC_MINT_SIZE, COUPON_SEED, TOKEN_2022_PROGRAM_ID};
use crate::error::ZupyTokenError;
use crate::helpers::cpi::{
    cpi_create_account, cpi_create_ata_if_needed, cpi_initialize_mint, cpi_mint_to,
};
use crate::helpers::instruction_data::{parse_bytes, parse_string};
use crate::helpers::pda::{derive_coupon_mint_pda, derive_user_nft_pda, validate_pda};
use crate::helpers::transfer_validation::validate_nft_payer;

/// Process `create_coupon_nft` instruction.
///
/// Creates a transferable coupon NFT: mint PDA + ATA + mint 1.
/// Coupon mint is self-authority (authority = coupon_mint PDA itself).
///
/// Accounts (8):
///   0. user_pda (read) — PDA [b"user_pda", &user_ksuid]
///   1. coupon_mint (writable) — PDA [b"coupon", &coupon_ksuid], init mint
///   2. coupon_ata (writable) — ATA for user_pda
///   3. token_state (read) — PDA [TOKEN_STATE_SEED], Audit 12.1
///   4. payer (writable, signer) — must match token_state.mint_authority()
///   5. token_program (read) — Token-2022
///   6. associated_token_program (read)
///   7. system_program (read)
///
/// Data: user_ksuid ([u8; 27]) + coupon_ksuid ([u8; 27]) + metadata_uri (String)
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // ── Account extraction (8 accounts) ─────────────────────────────────
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let user_pda = &accounts[0];
    let coupon_mint = &accounts[1];
    let coupon_ata = &accounts[2];
    let token_state_account = &accounts[3];
    let payer = &accounts[4];
    let token_program = &accounts[5];
    let _associated_token_program = &accounts[6];
    let system_program = &accounts[7];

    // ── Parse instruction data ──────────────────────────────────────────
    let (user_ksuid, offset) = parse_bytes::<27>(data, 0)?;
    let (coupon_ksuid, offset) = parse_bytes::<27>(data, offset)?;
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

    let (expected_coupon_mint, coupon_bump) = derive_coupon_mint_pda(program_id, coupon_ksuid);
    validate_pda(coupon_mint.address(), &expected_coupon_mint)?;

    // ── CPI 1: Create coupon mint PDA (82 bytes, owned by Token-2022) ───
    let coupon_bump_bytes = [coupon_bump];
    let mint_signer_seeds: [Seed; 3] = [
        Seed::from(COUPON_SEED),
        Seed::from(coupon_ksuid.as_ref()),
        Seed::from(coupon_bump_bytes.as_ref()),
    ];
    let mint_signer = Signer::from(&mint_signer_seeds);

    cpi_create_account(
        payer,
        coupon_mint,
        BASIC_MINT_SIZE,
        &token_2022_addr,
        &[mint_signer],
    )?;

    // ── CPI 2: Initialize mint (decimals=0, authority=coupon_mint PDA) ──
    cpi_initialize_mint(
        coupon_mint,
        &expected_coupon_mint,        // mint_authority = self
        Some(&expected_coupon_mint),   // freeze_authority = self
        0,                             // decimals = 0 for NFT
        &token_2022_addr,
    )?;

    // ── CPI 3: Create ATA for user_pda ──────────────────────────────────
    cpi_create_ata_if_needed(
        coupon_ata,
        payer,
        user_pda,
        coupon_mint,
        token_program,
        system_program,
    )?;

    // ── CPI 4: Mint 1 NFT to the ATA (coupon_mint PDA signs) ────────────
    let mint_signer_seeds2: [Seed; 3] = [
        Seed::from(COUPON_SEED),
        Seed::from(coupon_ksuid.as_ref()),
        Seed::from(coupon_bump_bytes.as_ref()),
    ];
    let mint_signer2 = Signer::from(&mint_signer_seeds2);

    cpi_mint_to(
        coupon_mint,
        coupon_ata,
        coupon_mint, // authority = coupon_mint PDA (self)
        1,
        &token_2022_addr,
        &[mint_signer2],
    )?;

    Ok(())
}
