//! Mollusk tests for `consolidate_leaves` (story 3.40).
//!
//! Basic Mollusk has no cToken, so "success" here = every check passed and the
//! CPI was attempted (`UnsupportedProgramId`). The real effect (the merged leaf
//! is spendable by its owner with the exact sum) is proven against the mainnet
//! binaries in `tests/test_mainnet_fork.rs`.
//!
//!   cargo build-sbf && SBF_OUT_DIR=target/deploy cargo test --test test_consolidate_leaves

mod helpers;

use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use helpers::*;

const DISC_CONSOLIDATE: [u8; 8] = [131, 243, 51, 130, 117, 203, 4, 156];

const OWNER_USER: u8 = 0;
const OWNER_COMPANY: u8 = 1;

const ERR_INVALID_AUTHORITY: u32 = 6000;
const ERR_INSUFFICIENT_BALANCE: u32 = 6004;
const ERR_INVALID_AMOUNT: u32 = 6005;
const ERR_INVALID_PDA: u32 = 6007;
const ERR_INVALID_MEMO_FORMAT: u32 = 6009;
const ERR_NOT_INITIALIZED: u32 = 6010;
const ERR_INVALID_MINT: u32 = 6011;
const ERR_ZERO_AMOUNT: u32 = 6012;
const ERR_SYSTEM_PAUSED: u32 = 6018;
const ERR_SPLIT_CALCULATION: u32 = 6029;

struct Setup {
    transfer_auth: Pubkey,
    token_state_pda: Pubkey,
    bump: u8,
    mint: Pubkey,
    fee_payer: Pubkey,
    kind: u8,
    owner_id: u64,
    owner_pda: Pubkey,
    owner_bump: u8,
    initialized: bool,
    paused: bool,
}

fn setup(kind: u8) -> Setup {
    let (token_state_pda, bump) = derive_token_state_pda();
    let owner_id = 77;
    let (owner_pda, owner_bump) =
        if kind == OWNER_COMPANY { derive_company_pda(owner_id) } else { derive_user_pda(owner_id) };
    Setup {
        transfer_auth: Pubkey::new_unique(),
        token_state_pda,
        bump,
        mint: Pubkey::new_unique(),
        fee_payer: Pubkey::new_unique(),
        kind,
        owner_id,
        owner_pda,
        owner_bump,
        initialized: true,
        paused: false,
    }
}

fn leaves(s: &Setup, amounts: &[u64], out: &[(Pubkey, u64)]) -> Vec<u8> {
    let inputs: Vec<V1Input> = amounts.iter().map(|a| V1Input::with_proof(*a)).collect();
    let outputs: Vec<(Pubkey, u64, u8)> = out.iter().map(|(o, a)| (*o, *a, 0u8)).collect();
    build_v1_transfer(&s.mint, Some([9u8; 128]), &inputs, &outputs)
}

fn payload(s: &Setup, amount: u64, memo: &str, v1: &[u8]) -> Vec<u8> {
    let mut p = vec![s.kind];
    p.extend_from_slice(&s.owner_id.to_le_bytes());
    p.push(s.owner_bump);
    p.extend_from_slice(&amount.to_le_bytes());
    p.extend_from_slice(&build_string(memo));
    p.extend_from_slice(v1);
    p
}

fn run(s: &Setup, data_payload: &[u8], cpi_authority: &Pubkey) -> mollusk_svm::result::InstructionResult {
    let mollusk = setup_mollusk();
    let ts_data = make_transfer_token_state(&s.transfer_auth, &s.mint, &Pubkey::new_unique(), s.bump, s.initialized, s.paused);
    let mut metas = vec![
        AccountMeta::new(s.transfer_auth, true),
        AccountMeta::new_readonly(s.token_state_pda, false),
        AccountMeta::new_readonly(s.mint, false),
        AccountMeta::new_readonly(s.owner_pda, false),
    ];
    metas.extend(v1_cpi_tail_metas(&s.fee_payer, cpi_authority));
    // The real tail carries the cToken as `self_program`; the CPI target must be in the tx.
    metas.push(AccountMeta::new_readonly(ctoken_program_id(), false));
    let mut accounts: Vec<(Pubkey, Account)> = vec![
        (s.transfer_auth, make_system_account(10_000_000)),
        (s.token_state_pda, make_program_account(ts_data, 1_000_000)),
        (s.mint, Account { lamports: 1_000_000, data: vec![0u8; 82], owner: token_2022_id(), executable: false, rent_epoch: 0 }),
        (s.owner_pda, make_program_account(vec![], 1_000_000)),
        (s.fee_payer, make_system_account(10_000_000)),
        make_program_stub(&ctoken_program_id()),
    ];
    if !accounts.iter().any(|(k, _)| k == cpi_authority) {
        accounts.push((*cpi_authority, make_system_account(0)));
    }
    let ix = Instruction::new_with_bytes(program_id(), &build_ix_data(&DISC_CONSOLIDATE, data_payload), metas);
    mollusk.process_instruction(&ix, &accounts)
}

fn good(s: &Setup, amounts: &[u64]) -> mollusk_svm::result::InstructionResult {
    let total: u64 = amounts.iter().sum();
    let v1 = leaves(s, amounts, &[(s.owner_pda, total)]);
    run(s, &payload(s, total, "zupy:v1:consolidate:1", &v1), &s.owner_pda)
}

fn reaches_cpi(r: &mollusk_svm::result::InstructionResult) {
    assert_eq!(r.raw_result, Err(InstructionError::UnsupportedProgramId), "must reach the cToken CPI");
}

// ── Success: every check passes and the CPI is attempted ───────────────────

#[test]
fn user_two_leaves_reach_cpi() {
    let r = good(&setup(OWNER_USER), &[300_000, 700_000]);
    reaches_cpi(&r);
    println!("consolidate_leaves (user, 2 leaves) validation CU={}", r.compute_units_consumed);
}

#[test]
fn company_eight_leaves_reach_cpi() {
    let r = good(&setup(OWNER_COMPANY), &[1, 2, 3, 4, 5, 6, 7, 8]);
    reaches_cpi(&r);
    println!("consolidate_leaves (company, 8 leaves) validation CU={}", r.compute_units_consumed);
}

#[test]
fn company_four_leaves_reach_cpi() {
    reaches_cpi(&good(&setup(OWNER_COMPANY), &[10, 20, 30, 40]));
}

// ── Header ─────────────────────────────────────────────────────────────────

#[test]
fn unknown_owner_kind_is_rejected() {
    let mut s = setup(OWNER_USER);
    s.kind = 2;
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

#[test]
fn company_id_with_user_kind_is_rejected() {
    // A company PDA declared as a USER owner: the derivation cannot match.
    let s0 = setup(OWNER_COMPANY);
    let s = Setup { kind: OWNER_USER, ..s0 };
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_PDA);
}

#[test]
fn wrong_owner_id_is_rejected() {
    let mut s = setup(OWNER_USER);
    s.owner_id = 78; // PDA account is still the one of id 77
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_PDA);
}

#[test]
fn zero_amount_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[0, 0], &[(s.owner_pda, 0)]);
    let r = run(&s, &payload(&s, 0, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_ZERO_AMOUNT);
}

#[test]
fn bad_memo_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "consolidate-7", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_MEMO_FORMAT);
}

#[test]
fn header_without_v1_fails_before_cpi() {
    let s = setup(OWNER_USER);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &[]), &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

#[test]
fn truncated_header_is_rejected() {
    let s = setup(OWNER_USER);
    let r = run(&s, &[OWNER_USER, 1, 2, 3], &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

// ── Common validation ──────────────────────────────────────────────────────

#[test]
fn paused_system_is_rejected() {
    let mut s = setup(OWNER_USER);
    s.paused = true;
    assert_ix_custom_err(&good(&s, &[1, 2]), ERR_SYSTEM_PAUSED);
}

#[test]
fn uninitialized_state_is_rejected() {
    let mut s = setup(OWNER_USER);
    s.initialized = false;
    assert_ix_custom_err(&good(&s, &[1, 2]), ERR_NOT_INITIALIZED);
}

#[test]
fn unsigned_transfer_authority_is_rejected() {
    let s = setup(OWNER_USER);
    let total = 3;
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, total)]);
    let mollusk = setup_mollusk();
    let ts_data = make_transfer_token_state(&s.transfer_auth, &s.mint, &Pubkey::new_unique(), s.bump, true, false);
    let mut metas = vec![
        AccountMeta::new(s.transfer_auth, false), // NOT a signer
        AccountMeta::new_readonly(s.token_state_pda, false),
        AccountMeta::new_readonly(s.mint, false),
        AccountMeta::new_readonly(s.owner_pda, false),
    ];
    metas.extend(v1_cpi_tail_metas(&s.fee_payer, &s.owner_pda));
    let accounts = vec![
        (s.transfer_auth, make_system_account(10_000_000)),
        (s.token_state_pda, make_program_account(ts_data, 1_000_000)),
        (s.mint, Account { lamports: 1_000_000, data: vec![0u8; 82], owner: token_2022_id(), executable: false, rent_epoch: 0 }),
        (s.owner_pda, make_program_account(vec![], 1_000_000)),
        (s.fee_payer, make_system_account(10_000_000)),
    ];
    let data = build_ix_data(&DISC_CONSOLIDATE, &payload(&s, total, "zupy:v1:consolidate:1", &v1));
    let r = mollusk.process_instruction(&Instruction::new_with_bytes(program_id(), &data, metas), &accounts);
    assert_ix_custom_err(&r, ERR_INVALID_AUTHORITY);
}

// ── Payload: the program executes a consolidation and nothing else ─────────

#[test]
fn single_leaf_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[5], &[(s.owner_pda, 5)]);
    let r = run(&s, &payload(&s, 5, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

#[test]
fn nine_leaves_are_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1; 9], &[(s.owner_pda, 9)]);
    let r = run(&s, &payload(&s, 9, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

#[test]
fn output_to_another_owner_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 2], &[(Pubkey::new_unique(), 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_PDA);
}

#[test]
fn extra_output_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 2), (s.owner_pda, 1)]);
    let r = run(&s, &payload(&s, 2, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_eq!(r.raw_result, Err(InstructionError::InvalidInstructionData));
}

#[test]
fn output_other_than_declared_amount_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 4, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_AMOUNT);
}

#[test]
fn inputs_short_of_declared_amount_is_insufficient_balance() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 1], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INSUFFICIENT_BALANCE);
}

#[test]
fn inputs_above_the_output_would_burn_and_are_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[2, 2], &[(s.owner_pda, 3)]);
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_SPLIT_CALCULATION);
}

#[test]
fn input_sum_overflow_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[u64::MAX, 1], &[(s.owner_pda, 1)]);
    let r = run(&s, &payload(&s, 1, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_SPLIT_CALCULATION);
}

#[test]
fn wrong_mint_in_payload_is_rejected() {
    let s = setup(OWNER_USER);
    let v1 = build_v1_transfer(
        &Pubkey::new_unique(), Some([9u8; 128]),
        &[V1Input::with_proof(1), V1Input::with_proof(2)], &[(s.owner_pda, 3, 0)],
    );
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &s.owner_pda);
    assert_ix_custom_err(&r, ERR_INVALID_MINT);
}

#[test]
fn cpi_authority_must_be_the_owner_pda() {
    let s = setup(OWNER_USER);
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let other = Pubkey::new_unique();
    let r = run(&s, &payload(&s, 3, "zupy:v1:consolidate:1", &v1), &other);
    assert_ix_custom_err(&r, ERR_INVALID_PDA);
}

#[test]
fn missing_cpi_accounts_is_not_enough_keys() {
    let s = setup(OWNER_USER);
    let mollusk = setup_mollusk();
    let v1 = leaves(&s, &[1, 2], &[(s.owner_pda, 3)]);
    let data = build_ix_data(&DISC_CONSOLIDATE, &payload(&s, 3, "zupy:v1:consolidate:1", &v1));
    let metas = vec![
        AccountMeta::new(s.transfer_auth, true),
        AccountMeta::new_readonly(s.token_state_pda, false),
        AccountMeta::new_readonly(s.mint, false),
    ];
    let accounts: Vec<(Pubkey, Account)> = metas.iter().map(|m| (m.pubkey, make_system_account(1))).collect();
    let r = mollusk.process_instruction(&Instruction::new_with_bytes(program_id(), &data, metas), &accounts);
    assert_ix_not_enough_keys(&r);
}
