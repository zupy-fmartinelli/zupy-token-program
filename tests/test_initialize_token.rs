//! Story 36.3 — initialize_token is pinned to the compile-time authorities.
//!
//! Only the treasury (`TREASURY_WALLET_PUBKEY`) may sign the one-time init, and
//! the three stored authorities must equal the constants. Otherwise anyone could
//! initialize a FRESH deployment first with their own keys (front-running).
//!
//! Requires `cargo build-sbf` before running:
//!   SBF_OUT_DIR=target/deploy cargo test --test test_initialize_token

mod helpers;

use helpers::*;
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const DISC_INITIALIZE_TOKEN: [u8; 8] = [38, 209, 150, 50, 190, 117, 16, 54];
const ERR_INVALID_AUTHORITY: u32 = 6000;
const ERR_UNAUTHORIZED_TREASURY: u32 = 6019;

fn empty() -> Account {
    Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }
}

/// Run initialize_token signed by `signer` with the three data pubkeys.
fn run_init(signer: Pubkey, treasury: Pubkey, mint_auth: Pubkey, transfer_auth: Pubkey) -> Result<(), InstructionError> {
    let mollusk = setup_mollusk();
    let (token_state_pda, _) = derive_token_state_pda();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let treasury_ata = Pubkey::new_unique();

    let mut payload = Vec::new();
    payload.extend_from_slice(treasury.as_ref());
    payload.extend_from_slice(mint_auth.as_ref());
    payload.extend_from_slice(transfer_auth.as_ref());
    let data = build_ix_data(&DISC_INITIALIZE_TOKEN, &payload);

    let metas = vec![
        AccountMeta::new(signer, true),
        AccountMeta::new(token_state_pda, false),
        AccountMeta::new(mint, true),
        AccountMeta::new(pool_ata, false),
        AccountMeta::new(treasury_ata, false),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(token_2022_id(), false),
        AccountMeta::new_readonly(ata_program_id(), false),
    ];
    let accounts = vec![
        (signer, make_system_account(100_000_000)),
        (token_state_pda, empty()),
        (mint, make_system_account(100_000_000)),
        (pool_ata, empty()),
        (treasury_ata, empty()),
        make_program_stub(&system_program_id()),
        make_program_stub(&token_2022_id()),
        make_program_stub(&ata_program_id()),
    ];
    mollusk.process_instruction(&Instruction::new_with_bytes(program_id(), &data, metas), &accounts).raw_result
}

/// With the treasury signing and the constant keys, every check passes and the
/// instruction reaches its first CPI (create_account on the system-program stub).
#[test]
fn test_init_with_treasury_and_constant_keys_reaches_cpi() {
    let r = run_init(treasury_wallet(), treasury_wallet(), mint_authority(), transfer_authority());
    assert_eq!(r, Err(InstructionError::UnsupportedProgramId));
}

#[test]
fn test_init_refuses_signer_other_than_treasury() {
    let r = run_init(Pubkey::new_unique(), treasury_wallet(), mint_authority(), transfer_authority());
    assert_eq!(r, Err(InstructionError::Custom(ERR_UNAUTHORIZED_TREASURY)));
}

#[test]
fn test_init_refuses_wrong_treasury_field() {
    let r = run_init(treasury_wallet(), Pubkey::new_unique(), mint_authority(), transfer_authority());
    assert_eq!(r, Err(InstructionError::Custom(ERR_UNAUTHORIZED_TREASURY)));
}

#[test]
fn test_init_refuses_wrong_mint_authority_field() {
    let r = run_init(treasury_wallet(), treasury_wallet(), Pubkey::new_unique(), transfer_authority());
    assert_eq!(r, Err(InstructionError::Custom(ERR_INVALID_AUTHORITY)));
}

#[test]
fn test_init_refuses_wrong_transfer_authority_field() {
    let r = run_init(treasury_wallet(), treasury_wallet(), mint_authority(), Pubkey::new_unique());
    assert_eq!(r, Err(InstructionError::Custom(ERR_INVALID_AUTHORITY)));
}
