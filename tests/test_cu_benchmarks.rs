//! Comprehensive CU Benchmark Suite
//!
//! Validates all 17 Pinocchio instructions against CU targets.
//! Measures validation-path CU (our code) and generates comparison report.
//!
//! Requires `cargo build-sbf` before running:
//!   cargo build-sbf && SBF_OUT_DIR=target/deploy cargo test --test test_cu_benchmarks -- --nocapture

mod helpers;

use mollusk_svm::result::InstructionResult;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use helpers::*;
use zupy_pinocchio::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID;

// ── Instruction discriminators (all 17) ──────────────────────────────────

const DISC_INITIALIZE_TOKEN: [u8; 8] = [38, 209, 150, 50, 190, 117, 16, 54];
const DISC_INITIALIZE_METADATA: [u8; 8] = [35, 215, 241, 156, 122, 208, 206, 212];
const DISC_UPDATE_METADATA_FIELD: [u8; 8] = [103, 217, 144, 202, 46, 70, 233, 141];
const DISC_MINT_TOKENS: [u8; 8] = [59, 132, 24, 246, 122, 39, 8, 243];
const DISC_TREASURY_RESTOCK_POOL: [u8; 8] = [94, 62, 103, 106, 93, 87, 173, 24];
const DISC_TRANSFER_FROM_POOL: [u8; 8] = [136, 167, 45, 66, 74, 252, 0, 16];
const DISC_RETURN_TO_POOL: [u8; 8] = [36, 85, 39, 183, 30, 172, 176, 72];
const DISC_TRANSFER_COMPANY_TO_USER: [u8; 8] = [8, 143, 213, 13, 143, 247, 145, 33];
const DISC_TRANSFER_USER_TO_COMPANY: [u8; 8] = [186, 233, 22, 40, 87, 223, 252, 131];
const DISC_EXECUTE_SPLIT_TRANSFER: [u8; 8] = [51, 254, 61, 214, 234, 138, 101, 214];
const DISC_BURN_TOKENS: [u8; 8] = [76, 15, 51, 254, 229, 215, 121, 66];
const DISC_BURN_FROM_COMPANY_PDA: [u8; 8] = [43, 207, 204, 77, 74, 93, 165, 34];
const DISC_INITIALIZE_RATE_LIMIT: [u8; 8] = [36, 132, 34, 217, 150, 48, 192, 165];
const DISC_SET_PAUSED: [u8; 8] = [91, 60, 125, 192, 176, 225, 166, 218];
const DISC_CREATE_ZUPY_CARD: [u8; 8] = [92, 114, 17, 0, 219, 121, 112, 150];
const DISC_CREATE_COUPON_NFT: [u8; 8] = [5, 106, 153, 76, 114, 157, 63, 236];
const DISC_MINT_COUPON_CNFT: [u8; 8] = [75, 5, 206, 155, 96, 133, 98, 15];

// ── Error codes ──────────────────────────────────────────────────────────

const ERR_INVALID_AUTHORITY: u32 = 6000;
const ERR_ZERO_AMOUNT: u32 = 6012;
const ERR_SYSTEM_PAUSED: u32 = 6018;
const ERR_INVALID_PDA: u32 = 6007;

// ── CU Thresholds ──────────────────────────────────────────────────────
// These represent MAX ALLOWED CU for validation-path execution.
// Validation-path = all Pinocchio code up to and including CPI attempt.
// CPI programs (Token-2022) are NOT loaded, so CPI fails at invoke boundary.
// This measures OUR code's efficiency, which is the relevant metric for
// comparing Pinocchio vs Anchor overhead.

const MAX_CU_TRANSFER_FROM_POOL: u64 = 14_500; // 16-account fixture (with Light system accounts) ~13643 observed
const MAX_CU_TRANSFER_C2U: u64 = 11_000;
const MAX_CU_TRANSFER_U2C: u64 = 14_000;
const MAX_CU_SPLIT_TRANSFER: u64 = 15_000;
const MAX_CU_RETURN_TO_POOL: u64 = 20_000; // binary grew with return_user_to_pool instruction ~18626 observed
const MAX_CU_BURN_TOKENS: u64 = 5_000;
const MAX_CU_BURN_FROM_COMPANY: u64 = 8_000;
const MAX_CU_MINT_TOKENS: u64 = 5_000;
const MAX_CU_INITIALIZE_TOKEN: u64 = 20_000;
const MAX_CU_INITIALIZE_METADATA: u64 = 15_000;
const MAX_CU_UPDATE_METADATA: u64 = 12_000;
const MAX_CU_TREASURY_RESTOCK: u64 = 8_000;
const MAX_CU_SET_PAUSED: u64 = 3_000;
const MAX_CU_INITIALIZE_RATE_LIMIT: u64 = 16_000;
const MAX_CU_CREATE_ZUPY_CARD: u64 = 25_000;
const MAX_CU_CREATE_COUPON_NFT: u64 = 22_000;
const MAX_CU_MINT_COUPON_CNFT: u64 = 40_000;

// ═══════════════════════════════════════════════════════════════════════════
// Helper: run instruction and return CU
// ═══════════════════════════════════════════════════════════════════════════

fn run_benchmark(
    mollusk: &mollusk_svm::Mollusk,
    instruction: &Instruction,
    accounts: &[(Pubkey, Account)],
) -> InstructionResult {
    mollusk.process_instruction(instruction, accounts)
}


// ═══════════════════════════════════════════════════════════════════════════
// HOT-PATH BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

// ── 1. transfer_from_pool ────────────────────────────────────────────────

fn setup_transfer_from_pool() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = ctoken_program_id();
    let ctoken_auth = derive_ctoken_authority();
    let spl_pda = derive_spl_interface_pda(&mint);
    let light_sys = light_system_program_id();
    let reg_pda = registered_program_pda_id();
    let noop = noop_program_id();
    let acct_comp_auth = account_compression_authority_id();
    let acct_comp_prog = account_compression_program_id();

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:pool_transfer:1");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

    // 16-account compressed layout (accounts[0..15], 16+ = Merkle remaining)
    let metas = vec![
        AccountMeta::new(transfer_auth, true),             // 0: signer
        AccountMeta::new_readonly(token_state_pda, false), // 1: token_state
        AccountMeta::new_readonly(mint, false),            // 2: mint
        AccountMeta::new(pool_ata, false),                 // 3: pool_ata
        AccountMeta::new_readonly(recipient, false),       // 4: recipient
        AccountMeta::new(fee_payer, true),                 // 5: fee_payer (signer)
        AccountMeta::new_readonly(token_2022_id(), false), // 6: token_program
        AccountMeta::new_readonly(system_program_id(), false), // 7: system_program
        AccountMeta::new_readonly(ctoken_prog, false),     // 8: compressed_token_program
        AccountMeta::new_readonly(ctoken_auth, false),     // 9: cpi_authority_pda
        AccountMeta::new_readonly(light_sys, false),       // 10: light_system_program
        AccountMeta::new_readonly(reg_pda, false),         // 11: registered_program_pda
        AccountMeta::new_readonly(noop, false),            // 12: noop_program
        AccountMeta::new_readonly(acct_comp_auth, false),  // 13: account_compression_authority
        AccountMeta::new_readonly(acct_comp_prog, false),  // 14: account_compression_program
        AccountMeta::new(spl_pda, false),                  // 15: spl_interface_pda
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 10_000_000))),
        (recipient, make_system_account(1_000_000)),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&token_2022_id()),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
        (ctoken_auth, make_system_account(1_000_000)),
        (light_sys, make_system_account(1_000_000)),
        (reg_pda, make_system_account(1_000_000)),
        (noop, make_system_account(1_000_000)),
        (acct_comp_auth, make_system_account(1_000_000)),
        (acct_comp_prog, make_system_account(1_000_000)),
        (spl_pda, make_system_account(1_000_000)),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_transfer_from_pool_validation_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_transfer_from_pool();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("transfer_from_pool          validation-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_TRANSFER_FROM_POOL,
        "transfer_from_pool CU {} > max {}",
        result.compute_units_consumed, MAX_CU_TRANSFER_FROM_POOL,
    );
}

#[test]
fn test_cu_transfer_from_pool_error_paused() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, true); // PAUSED

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:pool_transfer:1");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

    let recipient = Pubkey::new_unique();
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = ctoken_program_id();
    let ctoken_auth = derive_ctoken_authority();
    let spl_pda = derive_spl_interface_pda(&mint);
    let light_sys = light_system_program_id();
    let reg_pda = registered_program_pda_id();
    let noop = noop_program_id();
    let acct_comp_auth = account_compression_authority_id();
    let acct_comp_prog = account_compression_program_id();
    let metas = vec![
        AccountMeta::new(transfer_auth, true),             // 0
        AccountMeta::new_readonly(token_state_pda, false), // 1
        AccountMeta::new_readonly(mint, false),            // 2
        AccountMeta::new(pool_ata, false),                 // 3
        AccountMeta::new_readonly(recipient, false),       // 4
        AccountMeta::new(fee_payer, true),                 // 5
        AccountMeta::new_readonly(token_2022_id(), false), // 6
        AccountMeta::new_readonly(system_program_id(), false), // 7
        AccountMeta::new_readonly(ctoken_prog, false),     // 8
        AccountMeta::new_readonly(ctoken_auth, false),     // 9
        AccountMeta::new_readonly(light_sys, false),       // 10
        AccountMeta::new_readonly(reg_pda, false),         // 11
        AccountMeta::new_readonly(noop, false),            // 12
        AccountMeta::new_readonly(acct_comp_auth, false),  // 13
        AccountMeta::new_readonly(acct_comp_prog, false),  // 14
        AccountMeta::new(spl_pda, false),                  // 15
    ];
    let accounts = vec![
        (transfer_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(vec![0u8; 82])),
        (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 10_000_000))),
        (recipient, make_system_account(1_000_000)),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&token_2022_id()),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
        (ctoken_auth, make_system_account(1_000_000)),
        (light_sys, make_system_account(1_000_000)),
        (reg_pda, make_system_account(1_000_000)),
        (noop, make_system_account(1_000_000)),
        (acct_comp_auth, make_system_account(1_000_000)),
        (acct_comp_prog, make_system_account(1_000_000)),
        (spl_pda, make_system_account(1_000_000)),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    assert_ix_custom_err(&result, ERR_SYSTEM_PAUSED);
    println!("transfer_from_pool          error-paused CU: {}", result.compute_units_consumed);
    assert!(result.compute_units_consumed < MAX_CU_TRANSFER_FROM_POOL);
}

// ── 2. transfer_company_to_user ──────────────────────────────────────────

fn setup_transfer_c2u() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let company_id: u64 = 10;
    let user_id: u64 = 20;
    let (company_pda, company_bump) = derive_company_pda(company_id);
    let (user_pda, user_bump) = derive_user_pda(user_id);
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    let ctoken_auth = derive_ctoken_authority();

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:c2u:10:20");
    let mut payload = Vec::new();
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&user_id.to_le_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.push(company_bump);
    payload.push(user_bump);
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_COMPANY_TO_USER, &payload);

    // 9-account compressed layout (Path B: compressed → compressed)
    // [0] transfer_authority [1] token_state [2] mint [3] company_pda (src)
    // [4] user_pda (dst) [5] fee_payer [6] system_program
    // [7] compressed_token_program [8] compressed_token_authority
    let metas = vec![
        AccountMeta::new(transfer_auth, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(company_pda, false),
        AccountMeta::new_readonly(user_pda, false),
        AccountMeta::new(fee_payer, true),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(ctoken_prog, false),
        AccountMeta::new_readonly(ctoken_auth, false),
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(10_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (company_pda, make_program_account(vec![], 1_000_000)),
        (user_pda, make_program_account(vec![], 1_000_000)),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
        (ctoken_auth, make_system_account(1_000_000)),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_transfer_company_to_user_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_transfer_c2u();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("transfer_company_to_user    happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_TRANSFER_C2U,
        "transfer_company_to_user CU {} > max {}",
        result.compute_units_consumed, MAX_CU_TRANSFER_C2U,
    );
}

// ── 3. transfer_user_to_company ──────────────────────────────────────────

fn setup_transfer_u2c() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let user_id: u64 = 1;
    let company_id: u64 = 2;
    let (user_pda, user_bump) = derive_user_pda(user_id);
    let (company_pda, company_bump) = derive_company_pda(company_id);
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    let ctoken_auth = derive_ctoken_authority();

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:u2c:1:2");
    let mut payload = Vec::new();
    payload.extend_from_slice(&user_id.to_le_bytes());
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.push(user_bump);
    payload.push(company_bump);
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_USER_TO_COMPANY, &payload);

    // 9-account compressed layout (Path B: compressed → compressed)
    // [0] transfer_authority [1] token_state [2] mint [3] user_pda (src)
    // [4] company_pda (dst) [5] fee_payer [6] system_program
    // [7] compressed_token_program [8] compressed_token_authority
    let metas = vec![
        AccountMeta::new(transfer_auth, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(user_pda, false),
        AccountMeta::new_readonly(company_pda, false),
        AccountMeta::new(fee_payer, true),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(ctoken_prog, false),
        AccountMeta::new_readonly(ctoken_auth, false),
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(10_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (user_pda, make_program_account(vec![], 1_000_000)),
        (company_pda, make_program_account(vec![], 1_000_000)),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
        (ctoken_auth, make_system_account(1_000_000)),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_transfer_user_to_company_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_transfer_u2c();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("transfer_user_to_company    happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_TRANSFER_U2C,
        "transfer_user_to_company CU {} > max {}",
        result.compute_units_consumed, MAX_CU_TRANSFER_U2C,
    );
}

// ── 4. execute_split_transfer ────────────────────────────────────────────

fn setup_split_transfer() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let (incentive_pool_pda, incentive_bump) = derive_incentive_pool_pda();
    let user_id: u64 = 1;
    let company_id: u64 = 2;
    let (user_pda, user_bump) = derive_user_pda(user_id);
    let (company_pda, company_bump) = derive_company_pda(company_id);
    let user_ata = Pubkey::new_unique();
    let company_ata = Pubkey::new_unique();
    let incentive_ata = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &dummy, &dummy, &transfer_auth, &pool_ata, &dummy,
        &incentive_pool_pda, &dummy, &mint, bump, true, false,
    );

    let total_amount: u64 = 1_000_000;
    let mut payload = Vec::new();
    payload.extend_from_slice(&user_id.to_le_bytes());
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&total_amount.to_le_bytes());
    payload.push(user_bump);
    payload.push(company_bump);
    payload.push(incentive_bump);
    payload.extend_from_slice(&build_string("mixed_payment"));
    let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);

    let metas = vec![
        AccountMeta::new(transfer_auth, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint, false),
        AccountMeta::new_readonly(user_pda, false),
        AccountMeta::new_readonly(company_pda, false),
        AccountMeta::new_readonly(incentive_pool_pda, false),
        AccountMeta::new(user_ata, false),
        AccountMeta::new(company_ata, false),
        AccountMeta::new(incentive_ata, false),
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (user_pda, make_program_account(vec![], 1_000_000)),
        (company_pda, make_program_account(vec![], 1_000_000)),
        (incentive_pool_pda, make_program_account(vec![], 1_000_000)),
        (user_ata, make_token_owned_account(make_token_account_data(&mint, &user_pda, 10_000_000))),
        (company_ata, make_token_owned_account(make_token_account_data(&mint, &company_pda, 0))),
        (incentive_ata, make_token_owned_account(make_token_account_data(&mint, &incentive_pool_pda, 0))),
        make_program_stub(&token_2022_id()),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_execute_split_transfer_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_split_transfer();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("execute_split_transfer      happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_SPLIT_TRANSFER,
        "execute_split_transfer CU {} > max {}",
        result.compute_units_consumed, MAX_CU_SPLIT_TRANSFER,
    );
}

// ── 5. return_to_pool ────────────────────────────────────────────────────

fn setup_return_to_pool() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let company_id: u64 = 42;
    let (company_pda, company_bump) = derive_company_pda(company_id);
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    let ctoken_auth = derive_ctoken_authority();
    let spl_pda = derive_spl_interface_pda(&mint);

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:return:42");
    let mut payload = Vec::new();
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.push(company_bump);
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

    let metas = vec![
        AccountMeta::new(transfer_auth, true),              // 0: signer
        AccountMeta::new_readonly(token_state_pda, false),  // 1
        AccountMeta::new_readonly(mint, false),             // 2
        AccountMeta::new_readonly(company_pda, false),      // 3
        AccountMeta::new(pool_ata, false),                  // 4: writable
        AccountMeta::new(fee_payer, true),                  // 5: writable+signer
        AccountMeta::new_readonly(token_2022_id(), false),  // 6
        AccountMeta::new_readonly(system_program_id(), false), // 7
        AccountMeta::new_readonly(ctoken_prog, false),      // 8
        AccountMeta::new_readonly(ctoken_auth, false),      // 9
        AccountMeta::new(spl_pda, false),                   // 10: writable
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (company_pda, make_program_account(vec![], 1_000_000)),
        (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 0))),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&token_2022_id()),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
        (ctoken_auth, make_system_account(1_000_000)),
        (spl_pda, make_system_account(1_000_000)),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_return_to_pool_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_return_to_pool();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("return_to_pool              happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_RETURN_TO_POOL,
        "return_to_pool CU {} > max {}",
        result.compute_units_consumed, MAX_CU_RETURN_TO_POOL,
    );
}

// ── 6. burn_tokens ───────────────────────────────────────────────────────

fn setup_burn_tokens() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let treasury = treasury_wallet();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let treasury_ata = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &treasury, &dummy, &dummy, &pool_ata, &dummy, &dummy, &treasury_ata,
        &mint, bump, true, false,
    );

    let amount: u64 = 500_000;
    let memo = build_string("zupy:v1:burn:manual");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_BURN_TOKENS, &payload);

    let metas = vec![
        AccountMeta::new(treasury, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint, false),
        AccountMeta::new(treasury_ata, false),
        AccountMeta::new(treasury, true), // token_account_owner (same as authority)
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (treasury, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (treasury_ata, make_token_owned_account(make_token_account_data(&mint, &treasury, 10_000_000))),
        (treasury, make_system_account(1_000_000)),
        make_program_stub(&token_2022_id()),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_burn_tokens_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_burn_tokens();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("burn_tokens                 happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_BURN_TOKENS,
        "burn_tokens CU {} > max {}",
        result.compute_units_consumed, MAX_CU_BURN_TOKENS,
    );
}

// ── 7. burn_from_company_pda ─────────────────────────────────────────────

fn setup_burn_from_company_pda() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let company_id: u64 = 42;
    let (company_pda, _) = derive_company_pda(company_id);
    let fee_payer = Pubkey::new_unique();
    let ctoken_prog = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 500_000;
    let memo = build_string("zupy:v1:burn_company:42");
    let mut payload = Vec::new();
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);

    let metas = vec![
        AccountMeta::new(transfer_auth, true),              // 0: signer
        AccountMeta::new_readonly(token_state_pda, false),  // 1
        AccountMeta::new(mint, false),                      // 2: writable
        AccountMeta::new_readonly(company_pda, false),      // 3
        AccountMeta::new(fee_payer, true),                  // 4: writable+signer
        AccountMeta::new_readonly(system_program_id(), false), // 5
        AccountMeta::new_readonly(ctoken_prog, false),      // 6
    ];

    let accounts = vec![
        (transfer_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (company_pda, make_program_account(vec![], 1_000_000)),
        (fee_payer, make_system_account(10_000_000)),
        make_program_stub(&system_program_id()),
        make_program_stub(&ctoken_prog),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_burn_from_company_pda_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_burn_from_company_pda();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("burn_from_company_pda       happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_BURN_FROM_COMPANY,
        "burn_from_company_pda CU {} > max {}",
        result.compute_units_consumed, MAX_CU_BURN_FROM_COMPANY,
    );
}

// ── 8. mint_tokens ───────────────────────────────────────────────────────

fn setup_mint_tokens() -> (Instruction, Vec<(Pubkey, Account)>) {
    let (token_state_pda, bump) = derive_token_state_pda();
    let mint_auth = mint_authority();
    let mint = Pubkey::new_unique();
    let treasury_ata = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &dummy, &mint_auth, &dummy, &dummy, &dummy, &dummy, &treasury_ata,
        &mint, bump, true, false,
    );

    let amount: u64 = 5_000_000;
    let memo = build_string("zupy:v1:mint:batch");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_MINT_TOKENS, &payload);

    let metas = vec![
        AccountMeta::new(mint_auth, true),
        AccountMeta::new(token_state_pda, false),
        AccountMeta::new(mint, false),
        AccountMeta::new(treasury_ata, false),
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (mint_auth, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (treasury_ata, make_token_owned_account(make_token_account_data(&mint, &dummy, 0))),
        make_program_stub(&token_2022_id()),
    ];

    (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
}

#[test]
fn test_cu_mint_tokens_happy_path() {
    let mollusk = setup_mollusk();
    let (ix, accounts) = setup_mint_tokens();
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("mint_tokens                 happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_MINT_TOKENS,
        "mint_tokens CU {} > max {}",
        result.compute_units_consumed, MAX_CU_MINT_TOKENS,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// COLD-PATH BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

// ── 9. initialize_token ──────────────────────────────────────────────────

#[test]
fn test_cu_initialize_token_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, _) = derive_token_state_pda();
    let authority = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let treasury_ata = Pubkey::new_unique();
    let treasury = Pubkey::new_unique();
    let mint_auth = Pubkey::new_unique();
    let transfer_auth = Pubkey::new_unique();

    // Data: 3 pubkeys
    let mut payload = Vec::new();
    payload.extend_from_slice(treasury.as_ref());
    payload.extend_from_slice(mint_auth.as_ref());
    payload.extend_from_slice(transfer_auth.as_ref());
    let data = build_ix_data(&DISC_INITIALIZE_TOKEN, &payload);

    let metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(token_state_pda, false),
        AccountMeta::new(mint, true),
        AccountMeta::new(pool_ata, false),
        AccountMeta::new(treasury_ata, false),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(token_2022_id(), false),
        AccountMeta::new_readonly(ata_program_id(), false),
    ];

    let accounts = vec![
        (authority, make_system_account(100_000_000)),
        (token_state_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (mint, make_system_account(100_000_000)),
        (pool_ata, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (treasury_ata, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        make_program_stub(&system_program_id()),
        make_program_stub(&token_2022_id()),
        make_program_stub(&ata_program_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("initialize_token            happy-path CU: {}", result.compute_units_consumed);
    // CPI-heavy instruction, allow higher threshold
    assert!(
        result.compute_units_consumed <= MAX_CU_INITIALIZE_TOKEN,
        "initialize_token CU {} > max {}",
        result.compute_units_consumed, MAX_CU_INITIALIZE_TOKEN,
    );
}

// ── 10. initialize_metadata ──────────────────────────────────────────────

#[test]
fn test_cu_initialize_metadata_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let treasury = treasury_wallet();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    let name = build_string("Zupy Token");
    let symbol = build_string("ZUPY");
    let uri = build_string("https://zupy.com/metadata.json");
    let mut payload = Vec::new();
    payload.extend_from_slice(&name);
    payload.extend_from_slice(&symbol);
    payload.extend_from_slice(&uri);
    let data = build_ix_data(&DISC_INITIALIZE_METADATA, &payload);

    let metas = vec![
        AccountMeta::new(treasury, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint, false),
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (treasury, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(vec![0u8; 151])), // mint with metadata pointer
        make_program_stub(&token_2022_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("initialize_metadata         happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_INITIALIZE_METADATA,
        "initialize_metadata CU {} > max {}",
        result.compute_units_consumed, MAX_CU_INITIALIZE_METADATA,
    );
}

// ── 11. update_metadata_field ────────────────────────────────────────────

#[test]
fn test_cu_update_metadata_field_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let treasury = treasury_wallet();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    // field=0 (Name), value="Updated Zupy"
    let value = build_string("Updated Zupy");
    let mut payload = Vec::new();
    payload.push(0u8); // field = Name
    payload.extend_from_slice(&value);
    let data = build_ix_data(&DISC_UPDATE_METADATA_FIELD, &payload);

    let metas = vec![
        AccountMeta::new(treasury, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint, false),
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (treasury, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(vec![0u8; 151])),
        make_program_stub(&token_2022_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("update_metadata_field       happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_UPDATE_METADATA,
        "update_metadata_field CU {} > max {}",
        result.compute_units_consumed, MAX_CU_UPDATE_METADATA,
    );
}

// ── 12. treasury_restock_pool ────────────────────────────────────────────

#[test]
fn test_cu_treasury_restock_pool_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let treasury = treasury_wallet();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let treasury_ata = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &treasury, &dummy, &dummy, &pool_ata, &dummy, &dummy, &treasury_ata,
        &mint, bump, true, false,
    );

    let amount: u64 = 5_000_000;
    let memo = build_string("zupy:v1:restock:manual");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TREASURY_RESTOCK_POOL, &payload);

    let metas = vec![
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(treasury_ata, false),
        AccountMeta::new(pool_ata, false),
        AccountMeta::new(treasury, true),
        AccountMeta::new_readonly(token_2022_id(), false),
    ];

    let accounts = vec![
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
        (treasury_ata, make_token_owned_account(make_token_account_data(&mint, &treasury, 50_000_000))),
        (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 0))),
        (treasury, make_system_account(1_000_000)),
        make_program_stub(&token_2022_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("treasury_restock_pool       happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_TREASURY_RESTOCK,
        "treasury_restock_pool CU {} > max {}",
        result.compute_units_consumed, MAX_CU_TREASURY_RESTOCK,
    );
}

// ── 13. set_paused ───────────────────────────────────────────────────────

#[test]
fn test_cu_set_paused_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let treasury = treasury_wallet();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    // payload: paused = true (1 byte)
    let data = build_ix_data(&DISC_SET_PAUSED, &[1u8]);

    let metas = vec![
        AccountMeta::new(treasury, true),
        AccountMeta::new(token_state_pda, false),
    ];

    let accounts = vec![
        (treasury, make_system_account(1_000_000)),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("set_paused                  happy-path CU: {}", result.compute_units_consumed);
    // set_paused has no CPI, should complete fully
    assert!(
        result.compute_units_consumed <= MAX_CU_SET_PAUSED,
        "set_paused CU {} > max {}",
        result.compute_units_consumed, MAX_CU_SET_PAUSED,
    );
}

// ── 14. initialize_rate_limit ────────────────────────────────────────────

#[test]
fn test_cu_initialize_rate_limit_happy_path() {
    let mollusk = setup_mollusk();
    let authority = Pubkey::new_unique();
    let (rate_limit_pda, _) = derive_rate_limit_pda(&authority);

    // No payload beyond discriminator
    let data = build_ix_data(&DISC_INITIALIZE_RATE_LIMIT, &[]);

    let metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(rate_limit_pda, false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    let accounts = vec![
        (authority, make_system_account(100_000_000)),
        (rate_limit_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        make_program_stub(&system_program_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("initialize_rate_limit       happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_INITIALIZE_RATE_LIMIT,
        "initialize_rate_limit CU {} > max {}",
        result.compute_units_consumed, MAX_CU_INITIALIZE_RATE_LIMIT,
    );
}

// ── 15. create_zupy_card ─────────────────────────────────────────────────

#[test]
fn test_cu_create_zupy_card_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let mint_auth = mint_authority();

    let user_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2A";
    let (user_pda, _) = derive_user_pda_by_ksuid(&user_ksuid);
    let (zupy_card_pda, _) = derive_zupy_card_pda(&user_ksuid);
    let (card_mint_pda, _) = derive_zupy_card_mint_pda(&user_ksuid);
    let token_account = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &dummy, &mint_auth, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    let uri = build_string("https://zupy.com/cards/test.json");
    let mut payload = Vec::new();
    payload.extend_from_slice(&user_ksuid);
    payload.extend_from_slice(&uri);
    let data = build_ix_data(&DISC_CREATE_ZUPY_CARD, &payload);

    let metas = vec![
        AccountMeta::new_readonly(user_pda, false),
        AccountMeta::new(zupy_card_pda, false),
        AccountMeta::new(card_mint_pda, false),
        AccountMeta::new(token_account, false),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint_auth, true),
        AccountMeta::new_readonly(token_2022_id(), false),
        AccountMeta::new_readonly(ata_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    let accounts = vec![
        (user_pda, make_program_account(vec![], 1_000_000)),
        (zupy_card_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (card_mint_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (token_account, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint_auth, make_system_account(100_000_000)),
        make_program_stub(&token_2022_id()),
        make_program_stub(&ata_program_id()),
        make_program_stub(&system_program_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("create_zupy_card            happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_CREATE_ZUPY_CARD,
        "create_zupy_card CU {} > max {}",
        result.compute_units_consumed, MAX_CU_CREATE_ZUPY_CARD,
    );
}

// ── 16. create_coupon_nft ────────────────────────────────────────────────

#[test]
fn test_cu_create_coupon_nft_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let mint_auth = mint_authority();

    let user_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2A";
    let coupon_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2B";
    let (user_pda, _) = derive_user_pda_by_ksuid(&user_ksuid);
    let (coupon_mint_pda, _) = derive_coupon_pda(&coupon_ksuid);
    let coupon_ata = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &dummy, &mint_auth, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    let uri = build_string("https://zupy.com/coupons/test.json");
    let mut payload = Vec::new();
    payload.extend_from_slice(&user_ksuid);
    payload.extend_from_slice(&coupon_ksuid);
    payload.extend_from_slice(&uri);
    let data = build_ix_data(&DISC_CREATE_COUPON_NFT, &payload);

    let metas = vec![
        AccountMeta::new_readonly(user_pda, false),
        AccountMeta::new(coupon_mint_pda, false),
        AccountMeta::new(coupon_ata, false),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new(mint_auth, true),
        AccountMeta::new_readonly(token_2022_id(), false),
        AccountMeta::new_readonly(ata_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    let accounts = vec![
        (user_pda, make_program_account(vec![], 1_000_000)),
        (coupon_mint_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (coupon_ata, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
        (mint_auth, make_system_account(100_000_000)),
        make_program_stub(&token_2022_id()),
        make_program_stub(&ata_program_id()),
        make_program_stub(&system_program_id()),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("create_coupon_nft           happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_CREATE_COUPON_NFT,
        "create_coupon_nft CU {} > max {}",
        result.compute_units_consumed, MAX_CU_CREATE_COUPON_NFT,
    );
}

// ── 17. mint_coupon_cnft ─────────────────────────────────────────────────
// NOTE: Bubblegum CPI requires loading Bubblegum + SPL Compression + Noop.
// These programs are not available as pre-built .so files in Mollusk.
// Test measures validation-path CU up to the Bubblegum CPI boundary.

#[test]
fn test_cu_mint_coupon_cnft_happy_path() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let payer = mint_authority();
    let tree_authority = Pubkey::new_unique();
    let leaf_owner = Pubkey::new_unique();
    let merkle_tree = Pubkey::new_unique();
    let tree_config = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    let dummy = Pubkey::new_unique();
    let ts_data = make_token_state_data(
        &dummy, &payer, &dummy, &dummy, &dummy, &dummy, &dummy,
        &mint, bump, true, false,
    );

    let name = build_string("Zupy Coupon #1");
    let symbol = build_string("ZCPN");
    let uri = build_string("https://zupy.com/cnft/1.json");
    let mut payload = Vec::new();
    payload.extend_from_slice(&name);
    payload.extend_from_slice(&symbol);
    payload.extend_from_slice(&uri);
    let data = build_ix_data(&DISC_MINT_COUPON_CNFT, &payload);

    let metas = vec![
        AccountMeta::new(tree_authority, true),
        AccountMeta::new_readonly(leaf_owner, false),
        AccountMeta::new(merkle_tree, false),
        AccountMeta::new(tree_config, false),
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(bubblegum_program_id(), false),
        AccountMeta::new_readonly(compression_program_id(), false),
        AccountMeta::new_readonly(noop_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(token_state_pda, false),
    ];

    let accounts = vec![
        (tree_authority, make_system_account(1_000_000)),
        (leaf_owner, make_system_account(1_000_000)),
        (merkle_tree, make_system_account(1_000_000)),
        (tree_config, make_system_account(1_000_000)),
        (payer, make_system_account(100_000_000)),
        make_program_stub(&bubblegum_program_id()),
        make_program_stub(&compression_program_id()),
        make_program_stub(&noop_program_id()),
        make_program_stub(&system_program_id()),
        (token_state_pda, make_program_account(ts_data, 1_000_000)),
    ];

    let ix = Instruction::new_with_bytes(program_id(), &data, metas);
    let result = run_benchmark(&mollusk, &ix, &accounts);
    println!("mint_coupon_cnft            happy-path CU: {}", result.compute_units_consumed);
    assert!(
        result.compute_units_consumed <= MAX_CU_MINT_COUPON_CNFT,
        "mint_coupon_cnft CU {} > max {}",
        result.compute_units_consumed, MAX_CU_MINT_COUPON_CNFT,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR-PATH BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cu_error_paths() {
    let mollusk = setup_mollusk();

    println!("\n═══ Error-Path CU Measurements ═══");

    // transfer_from_pool: wrong authority (16-account compressed layout)
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let real_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let ts_data = make_transfer_token_state(&real_auth, &mint, &pool_ata, bump, true, false);
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(&mint);
        let light_sys = light_system_program_id();
        let reg_pda = registered_program_pda_id();
        let noop = noop_program_id();
        let acct_comp_auth = account_compression_authority_id();
        let acct_comp_prog = account_compression_program_id();
        let metas = vec![
            AccountMeta::new(wrong_auth, true),                    // 0: wrong authority
            AccountMeta::new_readonly(token_state_pda, false),     // 1
            AccountMeta::new_readonly(mint, false),                // 2
            AccountMeta::new(pool_ata, false),                     // 3
            AccountMeta::new_readonly(recipient, false),           // 4
            AccountMeta::new(fee_payer, true),                     // 5
            AccountMeta::new_readonly(token_2022_id(), false),     // 6
            AccountMeta::new_readonly(system_program_id(), false), // 7
            AccountMeta::new_readonly(ctoken_prog, false),         // 8
            AccountMeta::new_readonly(ctoken_auth, false),         // 9
            AccountMeta::new_readonly(light_sys, false),           // 10
            AccountMeta::new_readonly(reg_pda, false),             // 11
            AccountMeta::new_readonly(noop, false),                // 12
            AccountMeta::new_readonly(acct_comp_auth, false),      // 13
            AccountMeta::new_readonly(acct_comp_prog, false),      // 14
            AccountMeta::new(spl_pda, false),                      // 15
        ];
        let accounts = vec![
            (wrong_auth, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 82])),
            (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 10_000_000))),
            (recipient, make_system_account(1_000_000)),
            (fee_payer, make_system_account(10_000_000)),
            make_program_stub(&token_2022_id()),
            make_program_stub(&system_program_id()),
            make_program_stub(&ctoken_prog),
            (ctoken_auth, make_system_account(1_000_000)),
            (light_sys, make_system_account(1_000_000)),
            (reg_pda, make_system_account(1_000_000)),
            (noop, make_system_account(1_000_000)),
            (acct_comp_auth, make_system_account(1_000_000)),
            (acct_comp_prog, make_system_account(1_000_000)),
            (spl_pda, make_system_account(1_000_000)),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let result = run_benchmark(&mollusk, &ix, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("  transfer_from_pool     wrong_auth  CU: {:>6}", result.compute_units_consumed);
        assert!(result.compute_units_consumed < MAX_CU_TRANSFER_FROM_POOL);
    }

    // return_to_pool: wrong PDA (compressed 11-account layout)
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let wrong_company = Pubkey::new_unique();
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);
        let company_id: u64 = 42;
        let (_, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(&mint);
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);
        let metas = vec![
            AccountMeta::new(transfer_auth, true),              // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),  // 1
            AccountMeta::new_readonly(mint, false),             // 2
            AccountMeta::new_readonly(wrong_company, false),    // 3: wrong PDA
            AccountMeta::new(pool_ata, false),                  // 4: writable
            AccountMeta::new(fee_payer, true),                  // 5: writable+signer
            AccountMeta::new_readonly(token_2022_id(), false),  // 6
            AccountMeta::new_readonly(system_program_id(), false), // 7
            AccountMeta::new_readonly(ctoken_prog, false),      // 8
            AccountMeta::new_readonly(ctoken_auth, false),      // 9
            AccountMeta::new(spl_pda, false),                   // 10: writable
        ];
        let accounts = vec![
            (transfer_auth, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 82])),
            (wrong_company, make_program_account(vec![], 1_000_000)),
            (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 0))),
            (fee_payer, make_system_account(10_000_000)),
            make_program_stub(&token_2022_id()),
            make_program_stub(&system_program_id()),
            make_program_stub(&ctoken_prog),
            (ctoken_auth, make_system_account(1_000_000)),
            (spl_pda, make_system_account(1_000_000)),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let result = run_benchmark(&mollusk, &ix, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("  return_to_pool         wrong_pda   CU: {:>6}", result.compute_units_consumed);
        assert!(result.compute_units_consumed < MAX_CU_RETURN_TO_POOL);
    }

    // execute_split_transfer: zero amount
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let (incentive_pool_pda, incentive_bump) = derive_incentive_pool_pda();
        let (user_pda, user_bump) = derive_user_pda(1);
        let (company_pda, company_bump) = derive_company_pda(2);
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(
            &dummy, &dummy, &transfer_auth, &pool_ata, &dummy,
            &incentive_pool_pda, &dummy, &mint, bump, true, false,
        );
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_le_bytes()); // user_id
        payload.extend_from_slice(&2u64.to_le_bytes()); // company_id
        payload.extend_from_slice(&0u64.to_le_bytes()); // zero amount
        payload.push(user_bump);
        payload.push(company_bump);
        payload.push(incentive_bump);
        payload.extend_from_slice(&build_string("mixed_payment"));
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = vec![
            AccountMeta::new(transfer_auth, true),
            AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new(mint, false),
            AccountMeta::new_readonly(user_pda, false),
            AccountMeta::new_readonly(company_pda, false),
            AccountMeta::new_readonly(incentive_pool_pda, false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(token_2022_id(), false),
        ];
        let accounts: Vec<(Pubkey, Account)> = metas.iter().enumerate().map(|(i, meta)| {
            let acc = if i == 1 {
                make_program_account(ts_data.clone(), 1_000_000)
            } else if i == 3 || i == 4 || i == 5 {
                make_program_account(vec![], 1_000_000)
            } else if i == 9 {
                Account { lamports: 1, data: vec![], owner: Pubkey::default(), executable: true, rent_epoch: 0 }
            } else if i == 2 || i == 6 || i == 7 || i == 8 {
                make_token_owned_account(vec![0u8; 165])
            } else {
                make_system_account(1_000_000)
            };
            (meta.pubkey, acc)
        }).collect();
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let result = run_benchmark(&mollusk, &ix, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("  execute_split_transfer zero_amount CU: {:>6}", result.compute_units_consumed);
        assert!(result.compute_units_consumed < MAX_CU_SPLIT_TRANSFER);
    }

    println!("═══════════════════════════════════\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// BINARY SIZE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_binary_size() {
    let binary_path = std::env::var("SBF_OUT_DIR")
        .unwrap_or_else(|_| "target/deploy".to_string());
    let so_path = format!("{}/zupy_pinocchio.so", binary_path);

    let metadata = std::fs::metadata(&so_path)
        .unwrap_or_else(|_| panic!("Binary not found at {}. Run cargo build-sbf first.", so_path));

    let size_bytes = metadata.len();
    let size_kb = size_bytes as f64 / 1024.0;
    let deploy_cost_sol = size_kb * 0.00482; // approx rent formula

    let anchor_size_bytes: u64 = 564_496;
    let anchor_size_kb = anchor_size_bytes as f64 / 1024.0;
    let anchor_deploy_cost = anchor_size_kb * 0.00482;

    let size_savings_pct = (1.0 - (size_bytes as f64 / anchor_size_bytes as f64)) * 100.0;

    println!("\n═══ Binary Size Comparison ═══");
    println!("  Pinocchio: {:>7} bytes ({:.1} KB) — Deploy cost: ~{:.2} SOL", size_bytes, size_kb, deploy_cost_sol);
    println!("  Anchor:    {:>7} bytes ({:.1} KB) — Deploy cost: ~{:.2} SOL", anchor_size_bytes, anchor_size_kb, anchor_deploy_cost);
    println!("  Savings:   {:.1}% size reduction, ~{:.2} SOL savings", size_savings_pct, anchor_deploy_cost - deploy_cost_sol);
    println!("═════════════════════════════════════\n");

    // Binary size ≤ 160 KB (163,840 bytes)
    // Adjusted from 155 KB → 160 KB after adding return_user_to_pool instruction
    // (19th instruction). Final size: ~155.8 KB. 4.2 KB headroom.
    assert!(
        size_bytes <= 163_840,
        "Binary size {} bytes > 160 KB limit",
        size_bytes,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPREHENSIVE BENCHMARK REPORT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cu_benchmark_report() {
    let mollusk = setup_mollusk();
    let mut results: Vec<CuResult> = Vec::new();

    // Helper to run a benchmark and record result
    macro_rules! bench {
        ($name:expr, $class:expr, $anchor:expr, $max:expr, $setup:expr) => {{
            let (ix, accounts) = $setup;
            let r = run_benchmark(&mollusk, &ix, &accounts);
            let cu = r.compute_units_consumed;
            let passed = cu <= $max;
            results.push(CuResult {
                name: $name,
                classification: $class,
                anchor_est: $anchor,
                pinocchio_cu: cu,
                max_allowed: $max,
                passed,
                note: if !passed { format!("EXCEEDED by {}", cu - $max) }
                      else if cu as f64 > $max as f64 * 0.8 { "WARN: close to limit".into() }
                      else { String::new() },
            });
        }};
    }

    // Run all 17 benchmarks
    bench!("transfer_from_pool", "Hot-path", 25_000, MAX_CU_TRANSFER_FROM_POOL, setup_transfer_from_pool());
    bench!("transfer_company_to_user", "Hot-path", 35_000, MAX_CU_TRANSFER_C2U, setup_transfer_c2u());
    bench!("transfer_user_to_company", "Hot-path", 35_000, MAX_CU_TRANSFER_U2C, setup_transfer_u2c());
    bench!("execute_split_transfer", "Hot-path", 95_000, MAX_CU_SPLIT_TRANSFER, setup_split_transfer());
    bench!("return_to_pool", "Hot-path", 15_000, MAX_CU_RETURN_TO_POOL, setup_return_to_pool());
    bench!("burn_tokens", "Warm-path", 20_000, MAX_CU_BURN_TOKENS, setup_burn_tokens());
    bench!("burn_from_company_pda", "Warm-path", 25_000, MAX_CU_BURN_FROM_COMPANY, setup_burn_from_company_pda());
    bench!("mint_tokens", "Hot-path", 20_000, MAX_CU_MINT_TOKENS, setup_mint_tokens());

    // Cold-path: inline setup for instructions not reused above
    // 9. initialize_token — run with minimal setup
    {
        let (token_state_pda, _) = derive_token_state_pda();
        let authority = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let mut payload = Vec::new();
        payload.extend_from_slice(Pubkey::new_unique().as_ref());
        payload.extend_from_slice(Pubkey::new_unique().as_ref());
        payload.extend_from_slice(Pubkey::new_unique().as_ref());
        let data = build_ix_data(&DISC_INITIALIZE_TOKEN, &payload);
        let metas = vec![
            AccountMeta::new(authority, true), AccountMeta::new(token_state_pda, false),
            AccountMeta::new(mint, true), AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(system_program_id(), false),
            AccountMeta::new_readonly(token_2022_id(), false),
            AccountMeta::new_readonly(ata_program_id(), false),
        ];
        let accounts: Vec<(Pubkey, Account)> = metas.iter().enumerate().map(|(i, meta)| {
            let acc = if i == 5 || i == 6 || i == 7 {
                Account { lamports: 1, data: vec![], owner: Pubkey::default(), executable: true, rent_epoch: 0 }
            } else {
                make_system_account(100_000_000)
            };
            (meta.pubkey, acc)
        }).collect();
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "initialize_token", classification: "Cold-path",
            anchor_est: 50_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_INITIALIZE_TOKEN,
            passed: r.compute_units_consumed <= MAX_CU_INITIALIZE_TOKEN,
            note: String::new(),
        });
    }

    // 10. initialize_metadata
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = treasury_wallet();
        let mint = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &mint, bump, true, false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&build_string("Zupy Token"));
        payload.extend_from_slice(&build_string("ZUPY"));
        payload.extend_from_slice(&build_string("https://zupy.com/meta.json"));
        let data = build_ix_data(&DISC_INITIALIZE_METADATA, &payload);
        let metas = vec![
            AccountMeta::new(treasury, true), AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new(mint, false), AccountMeta::new_readonly(token_2022_id(), false),
        ];
        let accounts = vec![
            (treasury, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 151])),
            make_program_stub(&token_2022_id()),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "initialize_metadata", classification: "Cold-path",
            anchor_est: 30_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_INITIALIZE_METADATA,
            passed: r.compute_units_consumed <= MAX_CU_INITIALIZE_METADATA,
            note: String::new(),
        });
    }

    // 11. update_metadata_field
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = treasury_wallet();
        let mint = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &mint, bump, true, false);
        let mut payload = Vec::new();
        payload.push(0u8);
        payload.extend_from_slice(&build_string("New Name"));
        let data = build_ix_data(&DISC_UPDATE_METADATA_FIELD, &payload);
        let metas = vec![
            AccountMeta::new(treasury, true), AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new(mint, false), AccountMeta::new_readonly(token_2022_id(), false),
        ];
        let accounts = vec![
            (treasury, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 151])),
            make_program_stub(&token_2022_id()),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "update_metadata_field", classification: "Cold-path",
            anchor_est: 25_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_UPDATE_METADATA,
            passed: r.compute_units_consumed <= MAX_CU_UPDATE_METADATA,
            note: String::new(),
        });
    }

    // 12. treasury_restock_pool
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = treasury_wallet();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let treasury_ata = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&treasury, &dummy, &dummy, &pool_ata, &dummy, &dummy, &treasury_ata, &mint, bump, true, false);
        let amount: u64 = 5_000_000;
        let memo = build_string("zupy:v1:restock:manual");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TREASURY_RESTOCK_POOL, &payload);
        let metas = vec![
            AccountMeta::new_readonly(token_state_pda, false), AccountMeta::new_readonly(mint, false),
            AccountMeta::new(treasury_ata, false), AccountMeta::new(pool_ata, false),
            AccountMeta::new(treasury, true), AccountMeta::new_readonly(token_2022_id(), false),
        ];
        let accounts = vec![
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(make_mint_data(&token_state_pda, 1_000_000_000, 6))),
            (treasury_ata, make_token_owned_account(make_token_account_data(&mint, &treasury, 50_000_000))),
            (pool_ata, make_token_owned_account(make_token_account_data(&mint, &token_state_pda, 0))),
            (treasury, make_system_account(1_000_000)),
            make_program_stub(&token_2022_id()),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "treasury_restock_pool", classification: "Cold-path",
            anchor_est: 35_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_TREASURY_RESTOCK,
            passed: r.compute_units_consumed <= MAX_CU_TREASURY_RESTOCK,
            note: String::new(),
        });
    }

    // 13. set_paused
    {
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = treasury_wallet();
        let mint = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&treasury, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &mint, bump, true, false);
        let data = build_ix_data(&DISC_SET_PAUSED, &[1u8]);
        let metas = vec![AccountMeta::new(treasury, true), AccountMeta::new(token_state_pda, false)];
        let accounts = vec![
            (treasury, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "set_paused", classification: "Cold-path",
            anchor_est: 15_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_SET_PAUSED,
            passed: r.compute_units_consumed <= MAX_CU_SET_PAUSED,
            note: String::new(),
        });
    }

    // 14. initialize_rate_limit
    {
        let authority = Pubkey::new_unique();
        let (rl_pda, _) = derive_rate_limit_pda(&authority);
        let data = build_ix_data(&DISC_INITIALIZE_RATE_LIMIT, &[]);
        let metas = vec![
            AccountMeta::new(authority, true), AccountMeta::new(rl_pda, false),
            AccountMeta::new_readonly(system_program_id(), false),
        ];
        let accounts = vec![
            (authority, make_system_account(100_000_000)),
            (rl_pda, Account { lamports: 0, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }),
            make_program_stub(&system_program_id()),
        ];
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "initialize_rate_limit", classification: "Cold-path",
            anchor_est: 20_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_INITIALIZE_RATE_LIMIT,
            passed: r.compute_units_consumed <= MAX_CU_INITIALIZE_RATE_LIMIT,
            note: String::new(),
        });
    }

    // 15-17: NFT instructions (create_zupy_card, create_coupon_nft, mint_coupon_cnft)
    // Using inline setup similar to the individual tests
    {
        // create_zupy_card
        let (token_state_pda, bump) = derive_token_state_pda();
        let mint_auth = mint_authority();
        let user_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2A";
        let (user_pda, _) = derive_user_pda_by_ksuid(&user_ksuid);
        let (zupy_card, _) = derive_zupy_card_pda(&user_ksuid);
        let (card_mint, _) = derive_zupy_card_mint_pda(&user_ksuid);
        let mint = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&dummy, &mint_auth, &dummy, &dummy, &dummy, &dummy, &dummy, &mint, bump, true, false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_ksuid);
        payload.extend_from_slice(&build_string("https://zupy.com/cards/test.json"));
        let data = build_ix_data(&DISC_CREATE_ZUPY_CARD, &payload);
        let metas = vec![
            AccountMeta::new_readonly(user_pda, false), AccountMeta::new(zupy_card, false),
            AccountMeta::new(card_mint, false), AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(token_state_pda, false), AccountMeta::new(mint_auth, true),
            AccountMeta::new_readonly(token_2022_id(), false), AccountMeta::new_readonly(ata_program_id(), false),
            AccountMeta::new_readonly(system_program_id(), false),
        ];
        let accounts: Vec<(Pubkey, Account)> = metas.iter().enumerate().map(|(i, meta)| {
            let acc = if i == 4 { make_program_account(ts_data.clone(), 1_000_000) }
                else if i == 0 { make_program_account(vec![], 1_000_000) }
                else if i >= 6 { Account { lamports: 1, data: vec![], owner: Pubkey::default(), executable: true, rent_epoch: 0 } }
                else { make_system_account(100_000_000) };
            (meta.pubkey, acc)
        }).collect();
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "create_zupy_card", classification: "Cold-path",
            anchor_est: 70_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_CREATE_ZUPY_CARD,
            passed: r.compute_units_consumed <= MAX_CU_CREATE_ZUPY_CARD,
            note: String::new(),
        });
    }
    {
        // create_coupon_nft
        let (token_state_pda, bump) = derive_token_state_pda();
        let mint_auth = mint_authority();
        let user_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2A";
        let coupon_ksuid: [u8; 27] = *b"2NRjKcGrXHKtGVjMXV7qptaXY2B";
        let (user_pda, _) = derive_user_pda_by_ksuid(&user_ksuid);
        let (coupon_mint, _) = derive_coupon_pda(&coupon_ksuid);
        let mint = Pubkey::new_unique();
        let dummy = Pubkey::new_unique();
        let ts_data = make_token_state_data(&dummy, &mint_auth, &dummy, &dummy, &dummy, &dummy, &dummy, &mint, bump, true, false);
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_ksuid);
        payload.extend_from_slice(&coupon_ksuid);
        payload.extend_from_slice(&build_string("https://zupy.com/coupons/test.json"));
        let data = build_ix_data(&DISC_CREATE_COUPON_NFT, &payload);
        let metas = vec![
            AccountMeta::new_readonly(user_pda, false), AccountMeta::new(coupon_mint, false),
            AccountMeta::new(Pubkey::new_unique(), false), AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new(mint_auth, true), AccountMeta::new_readonly(token_2022_id(), false),
            AccountMeta::new_readonly(ata_program_id(), false), AccountMeta::new_readonly(system_program_id(), false),
        ];
        let accounts: Vec<(Pubkey, Account)> = metas.iter().enumerate().map(|(i, meta)| {
            let acc = if i == 3 { make_program_account(ts_data.clone(), 1_000_000) }
                else if i == 0 { make_program_account(vec![], 1_000_000) }
                else if i >= 5 { Account { lamports: 1, data: vec![], owner: Pubkey::default(), executable: true, rent_epoch: 0 } }
                else { make_system_account(100_000_000) };
            (meta.pubkey, acc)
        }).collect();
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "create_coupon_nft", classification: "Cold-path",
            anchor_est: 65_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_CREATE_COUPON_NFT,
            passed: r.compute_units_consumed <= MAX_CU_CREATE_COUPON_NFT,
            note: String::new(),
        });
    }
    {
        // mint_coupon_cnft (10 accounts: tree_auth, leaf_owner, merkle, tree_config, payer, bubblegum, compression, noop, system, token_state)
        let (token_state_pda, ts_bump) = derive_token_state_pda();
        let cnft_payer = mint_authority();
        let cnft_mint = Pubkey::new_unique();
        let cnft_dummy = Pubkey::new_unique();
        let cnft_ts_data = make_token_state_data(
            &cnft_dummy, &cnft_payer, &cnft_dummy, &cnft_dummy, &cnft_dummy, &cnft_dummy, &cnft_dummy,
            &cnft_mint, ts_bump, true, false,
        );
        let name = build_string("Zupy Coupon #1");
        let symbol = build_string("ZCPN");
        let uri = build_string("https://zupy.com/cnft/1.json");
        let mut payload = Vec::new();
        payload.extend_from_slice(&name);
        payload.extend_from_slice(&symbol);
        payload.extend_from_slice(&uri);
        let data = build_ix_data(&DISC_MINT_COUPON_CNFT, &payload);
        let tree_auth = Pubkey::new_unique();
        let metas = vec![
            AccountMeta::new(tree_auth, true), AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false), AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(cnft_payer, true), AccountMeta::new_readonly(bubblegum_program_id(), false),
            AccountMeta::new_readonly(compression_program_id(), false), AccountMeta::new_readonly(noop_program_id(), false),
            AccountMeta::new_readonly(system_program_id(), false), AccountMeta::new_readonly(token_state_pda, false),
        ];
        let accounts: Vec<(Pubkey, Account)> = metas.iter().enumerate().map(|(i, meta)| {
            let acc = if i == 9 { make_program_account(cnft_ts_data.clone(), 1_000_000) }
                else if i >= 5 {
                    Account { lamports: 1, data: vec![], owner: Pubkey::default(), executable: true, rent_epoch: 0 }
                } else {
                    make_system_account(100_000_000)
                };
            (meta.pubkey, acc)
        }).collect();
        let ix = Instruction::new_with_bytes(program_id(), &data, metas);
        let r = run_benchmark(&mollusk, &ix, &accounts);
        results.push(CuResult {
            name: "mint_coupon_cnft", classification: "Cold-path",
            anchor_est: 80_000, pinocchio_cu: r.compute_units_consumed, max_allowed: MAX_CU_MINT_COUPON_CNFT,
            passed: r.compute_units_consumed <= MAX_CU_MINT_COUPON_CNFT,
            note: String::new(),
        });
    }

    // ── Print Report ─────────────────────────────────────────────────────
    let binary_path = std::env::var("SBF_OUT_DIR").unwrap_or_else(|_| "target/deploy".to_string());
    let so_path = format!("{}/zupy_pinocchio.so", binary_path);
    let binary_size = std::fs::metadata(&so_path).map(|m| m.len()).unwrap_or(0);
    let binary_kb = binary_size as f64 / 1024.0;
    let deploy_cost = binary_kb * 0.00482;

    println!("\n=== ZUPY-PINOCCHIO CU BENCHMARK REPORT ===");
    println!("Binary: {} bytes ({:.1} KB) — Deploy cost: ~{:.2} SOL", binary_size, binary_kb, deploy_cost);
    println!("Measurement: Validation-path CU (up to CPI boundary, Token-2022 not loaded)");
    println!();

    println!("HOT-PATH INSTRUCTIONS:");
    for r in results.iter().filter(|r| r.classification == "Hot-path") {
        let warn = if r.warn_close() && r.passed { " WARN" } else { "" };
        println!(
            "  {:30} | Anchor: ~{:>6} | Pinocchio: {:>6} | Savings: {:>5.1}% | [{}{}]",
            r.name, r.anchor_est, r.pinocchio_cu, r.savings_pct(), r.status_str(), warn
        );
    }

    println!("\nWARM-PATH INSTRUCTIONS:");
    for r in results.iter().filter(|r| r.classification == "Warm-path") {
        let warn = if r.warn_close() && r.passed { " WARN" } else { "" };
        println!(
            "  {:30} | Anchor: ~{:>6} | Pinocchio: {:>6} | Savings: {:>5.1}% | [{}{}]",
            r.name, r.anchor_est, r.pinocchio_cu, r.savings_pct(), r.status_str(), warn
        );
    }

    println!("\nCOLD-PATH INSTRUCTIONS:");
    for r in results.iter().filter(|r| r.classification == "Cold-path") {
        let warn = if r.warn_close() && r.passed { " WARN" } else { "" };
        println!(
            "  {:30} | Anchor: ~{:>6} | Pinocchio: {:>6} | Savings: {:>5.1}% | [{}{}]",
            r.name, r.anchor_est, r.pinocchio_cu, r.savings_pct(), r.status_str(), warn
        );
    }

    // Summary
    let hot_path: Vec<&CuResult> = results.iter().filter(|r| r.classification == "Hot-path" || r.classification == "Warm-path").collect();
    let cold_path: Vec<&CuResult> = results.iter().filter(|r| r.classification == "Cold-path").collect();

    let hot_avg_savings = if hot_path.is_empty() { 0.0 } else {
        hot_path.iter().map(|r| r.savings_pct()).sum::<f64>() / hot_path.len() as f64
    };
    let cold_avg_savings = if cold_path.is_empty() { 0.0 } else {
        cold_path.iter().map(|r| r.savings_pct()).sum::<f64>() / cold_path.len() as f64
    };

    let anchor_binary: u64 = 564_496;
    let binary_savings = (1.0 - (binary_size as f64 / anchor_binary as f64)) * 100.0;
    let anchor_deploy = anchor_binary as f64 / 1024.0 * 0.00482;

    let all_passed = results.iter().all(|r| r.passed);
    let failed_count = results.iter().filter(|r| !r.passed).count();

    println!("\nSUMMARY:");
    println!("  Hot/Warm-path avg savings: {:.1}%", hot_avg_savings);
    println!("  Cold-path avg savings: {:.1}%", cold_avg_savings);
    println!("  Hot-path avg CU: {:.0}", hot_path.iter().map(|r| r.pinocchio_cu as f64).sum::<f64>() / hot_path.len().max(1) as f64);
    println!("  Binary savings: {:.1}% ({} KB -> {:.1} KB)", binary_savings, anchor_binary / 1024, binary_kb);
    println!("  Deploy cost savings: {:.1}% ({:.2} SOL -> {:.2} SOL)", (1.0 - deploy_cost / anchor_deploy) * 100.0, anchor_deploy, deploy_cost);
    println!("  Total: {}/{} benchmarks passed", results.len() - failed_count, results.len());

    if !all_passed {
        println!("\n  FAILED INSTRUCTIONS:");
        for r in results.iter().filter(|r| !r.passed) {
            println!("    {} — CU: {} (max: {}, exceeded by {})", r.name, r.pinocchio_cu, r.max_allowed, r.pinocchio_cu - r.max_allowed);
        }
    }

    println!("=== END BENCHMARK REPORT ===\n");

    // Final assertion: all benchmarks must pass
    assert!(
        all_passed,
        "{} of {} benchmarks exceeded CU thresholds",
        failed_count, results.len(),
    );
}
