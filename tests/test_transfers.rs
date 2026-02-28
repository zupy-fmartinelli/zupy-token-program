//! Mollusk integration tests for Hot-Path Transfers.
//!
//! Tests all 4 transfer instructions:
//!   - transfer_from_pool
//!   - transfer_company_to_user
//!   - transfer_user_to_company
//!   - return_to_pool
//!
//! Requires `cargo build-sbf` before running:
//!   cargo build-sbf && cargo test --test test_transfers -- --nocapture

mod helpers;

use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction::error::InstructionError;
use solana_pubkey::Pubkey;

use helpers::*;

// ── Instruction discriminators ─────────────────────────────────────────────
const DISC_TRANSFER_FROM_POOL: [u8; 8] = [136, 167, 45, 66, 74, 252, 0, 16];
const DISC_RETURN_TO_POOL: [u8; 8] = [36, 85, 39, 183, 30, 172, 176, 72];
const DISC_TRANSFER_COMPANY_TO_USER: [u8; 8] = [8, 143, 213, 13, 143, 247, 145, 33];
const DISC_TRANSFER_USER_TO_COMPANY: [u8; 8] = [186, 233, 22, 40, 87, 223, 252, 131];

// ── Error codes from ZupyTokenError ──────────────────────────────────────
const ERR_INVALID_AUTHORITY: u32 = 6000;
const ERR_INSUFFICIENT_BALANCE: u32 = 6004;
const ERR_INVALID_PDA: u32 = 6007;
const ERR_INVALID_MEMO_FORMAT: u32 = 6009;
const ERR_NOT_INITIALIZED: u32 = 6010;
const ERR_INVALID_MINT: u32 = 6011;
const ERR_ZERO_AMOUNT: u32 = 6012;
const ERR_INVALID_POOL_ACCOUNT: u32 = 6017;
const ERR_SYSTEM_PAUSED: u32 = 6018;
const ERR_INSUFFICIENT_POOL_BALANCE: u32 = 6024;
const ERR_INVALID_TOKEN_PROGRAM: u32 = 6025;

// ── CU threshold for validation-path benchmarks ──────────────────────────
/// Maximum CU allowed for validation-path (includes PDA derivation + CPI attempt).
/// Observed values: ~4700 (single PDA) to ~9400 (dual PDA + ATA validation).
/// Anchor baseline was ~30K-40K CU; threshold at 15K enforces the optimization.
const CU_VALIDATION_THRESHOLD: u64 = 15_000;

// ═══════════════════════════════════════════════════════════════════════════
// transfer_from_pool tests
// ═══════════════════════════════════════════════════════════════════════════

mod transfer_from_pool {
    use super::*;

    /// Build the 16-account set for transfer_from_pool (with Light system accounts).
    /// Uses a random ctoken authority and real spl_interface_pda (for full validation path).
    pub(super) fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        pool_ata: &Pubkey,
        pool_balance: u64,
        recipient: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);
        let light_sys = light_system_program_id();
        let reg_pda = registered_program_pda_id();
        let noop = noop_program_id();
        let acct_comp_auth = account_compression_authority_id();
        let acct_comp_prog = account_compression_program_id();
        vec![
            // 0: transfer_authority (signer)
            (*transfer_auth, make_system_account(1_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (read)
            (*mint, Account {
                lamports: 1_000_000,
                data: vec![0u8; 82],
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }),
            // 3: pool_ata (writable)
            (*pool_ata, Account {
                lamports: 1_000_000,
                data: make_token_account_data(mint, token_state_pda, pool_balance),
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }),
            // 4: recipient (read)
            (*recipient, make_system_account(1_000_000)),
            // 5: fee_payer (writable, signer)
            (*fee_payer, make_system_account(10_000_000)),
            // 6: token_program (read) — Token-2022
            make_program_stub(&token_2022_id()),
            // 7: system_program (read)
            make_program_stub(&system_program_id()),
            // 8: compressed_token_program (read)
            make_program_stub(&ctoken_prog),
            // 9: compressed_token_authority (read) — placeholder PDA
            (ctoken_auth, make_system_account(1_000_000)),
            // 10-15: Light system accounts
            (light_sys, make_system_account(1_000_000)),
            (reg_pda, make_system_account(1_000_000)),
            (noop, make_system_account(1_000_000)),
            (acct_comp_auth, make_system_account(1_000_000)),
            (acct_comp_prog, make_system_account(1_000_000)),
            // 16: spl_interface_pda (writable) — derived from [b"pool", mint]
            (spl_pda, make_system_account(1_000_000)),
        ]
    }

    pub(super) fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        pool_ata: &Pubkey,
        recipient: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<AccountMeta> {
        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);
        let light_sys = light_system_program_id();
        let reg_pda = registered_program_pda_id();
        let noop = noop_program_id();
        let acct_comp_auth = account_compression_authority_id();
        let acct_comp_prog = account_compression_program_id();
        vec![
            AccountMeta::new(*transfer_auth, true),             // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false), // 1: read
            AccountMeta::new_readonly(*mint, false),            // 2: read
            AccountMeta::new(*pool_ata, false),                 // 3: writable
            AccountMeta::new_readonly(*recipient, false),       // 4: read
            AccountMeta::new(*fee_payer, true),                 // 5: writable, signer
            AccountMeta::new_readonly(token_2022_id(), false),  // 6: token_program
            AccountMeta::new_readonly(system_program_id(), false), // 7: system_program
            AccountMeta::new_readonly(ctoken_prog, false),      // 8: ctoken program
            AccountMeta::new_readonly(ctoken_auth, false),      // 9: ctoken authority
            // 10-15: Light system accounts
            AccountMeta::new_readonly(light_sys, false),
            AccountMeta::new_readonly(reg_pda, false),
            AccountMeta::new_readonly(noop, false),
            AccountMeta::new_readonly(acct_comp_auth, false),
            AccountMeta::new_readonly(acct_comp_prog, false),
            AccountMeta::new(spl_pda, false),                   // 16: spl_interface_pda
        ]
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        // Only pass 5 accounts (need 16)
        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ]);

        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("transfer_from_pool: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 0; // ZERO
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("transfer_from_pool: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, true); // PAUSED

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_SYSTEM_PAUSED);
        println!("transfer_from_pool: system_paused CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_transfer_authority() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique(); // WRONG authority
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        // Use wrong_auth as signer
        let metas = build_ix_metas(&wrong_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&wrong_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);
        accounts[0].0 = wrong_auth;

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("transfer_from_pool: wrong_authority CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_pool_ata() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let wrong_pool = Pubkey::new_unique(); // WRONG pool
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        // Pass wrong pool ATA
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &wrong_pool, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &wrong_pool, 1_000_000, &recipient, &fee_payer);
        accounts[3].0 = wrong_pool;

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_POOL_ACCOUNT);
        println!("transfer_from_pool: invalid_pool_ata CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_insufficient_pool_balance() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 10_000_000; // More than balance (1_000_000)
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INSUFFICIENT_POOL_BALANCE);
        println!("transfer_from_pool: insufficient_balance CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_fee_payer_not_signer() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        // fee_payer is NOT a signer
        let mut metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        metas[5] = AccountMeta::new(fee_payer, false); // NOT signer (index 5 in new layout)
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("transfer_from_pool: fee_payer_not_signer CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_initialized() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        // NOT initialized
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, false, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &pool_ata, &recipient, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &pool_ata, 1_000_000, &recipient, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_NOT_INITIALIZED);
        println!("transfer_from_pool: not_initialized CU={}", result.compute_units_consumed);
    }

    // Note on full-flow test:
    // A complete compress-to-leaf integration test requires the Light Protocol cToken
    // program loaded in Mollusk (via light-program-test or a mock). This is deferred
    // because the ZK Compression CLI (`@lightprotocol/zk-compression-cli`) is not
    // installed in this environment. All validation-path tests above verify that:
    // - Account count check updated to 11 (was 10)
    // - Error paths before the CPI all work correctly with the new account layout
    // Full CPI path is validated on devnet via manual transaction testing.
}

// ═══════════════════════════════════════════════════════════════════════════
// return_to_pool tests (compressed layout — 11 accounts minimum)
// ═══════════════════════════════════════════════════════════════════════════

mod return_to_pool {
    use super::*;

    /// Build the 11-account set for return_to_pool (compressed layout).
    pub(super) fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        company_pda: &Pubkey,
        pool_ata: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);
        vec![
            // 0: transfer_authority (signer)
            (*transfer_auth, make_system_account(1_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (read)
            (*mint, Account {
                lamports: 1_000_000,
                data: vec![0u8; 82],
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }),
            // 3: company_pda (read)
            (*company_pda, make_program_account(vec![], 1_000_000)),
            // 4: pool_ata (writable)
            (*pool_ata, Account {
                lamports: 1_000_000,
                data: make_token_account_data(mint, token_state_pda, 0),
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }),
            // 5: fee_payer (writable, signer)
            (*fee_payer, make_system_account(10_000_000)),
            // 6: token_program (read) — Token-2022 (spl_token_program for Light)
            make_program_stub(&token_2022_id()),
            // 7: system_program (read)
            make_program_stub(&system_program_id()),
            // 8: compressed_token_program (read)
            make_program_stub(&ctoken_prog),
            // 9: compressed_token_authority (read)
            (ctoken_auth, make_system_account(1_000_000)),
            // 10: spl_interface_pda (writable)
            (spl_pda, make_system_account(1_000_000)),
        ]
    }

    pub(super) fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        company_pda: &Pubkey,
        pool_ata: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<AccountMeta> {
        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);
        vec![
            AccountMeta::new(*transfer_auth, true),                    // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false),         // 1: read
            AccountMeta::new_readonly(*mint, false),                    // 2: read
            AccountMeta::new_readonly(*company_pda, false),             // 3: read
            AccountMeta::new(*pool_ata, false),                         // 4: writable
            AccountMeta::new(*fee_payer, true),                         // 5: writable, signer
            AccountMeta::new_readonly(token_2022_id(), false),          // 6: token_program
            AccountMeta::new_readonly(system_program_id(), false),      // 7: system_program
            AccountMeta::new_readonly(ctoken_prog, false),              // 8: ctoken program
            AccountMeta::new_readonly(ctoken_auth, false),              // 9: ctoken authority
            AccountMeta::new(spl_pda, false),                           // 10: spl_interface_pda
        ]
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let company_id: u64 = 42;
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
        ]);

        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("return_to_pool: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 0; // ZERO
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &pool_ata, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &pool_ata, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("return_to_pool: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_company_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 42;
        let wrong_company = Pubkey::new_unique(); // WRONG PDA
        let (_, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &wrong_company, &pool_ata, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &wrong_company, &pool_ata, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("return_to_pool: wrong_company_pda CU={}", result.compute_units_consumed);
    }

    /// Balance check removed (Light handles it). Test fee_payer signer check instead.
    #[test]
    fn test_fee_payer_not_signer() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

        let ctoken_prog = ctoken_program_id();
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(&mint);
        // fee_payer passed as non-signer (false)
        let metas = vec![
            AccountMeta::new(transfer_auth, true),
            AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(company_pda, false),
            AccountMeta::new(pool_ata, false),
            AccountMeta::new(fee_payer, false), // NOT signer
            AccountMeta::new_readonly(token_2022_id(), false),
            AccountMeta::new_readonly(system_program_id(), false),
            AccountMeta::new_readonly(ctoken_prog, false),
            AccountMeta::new_readonly(ctoken_auth, false),
            AccountMeta::new(spl_pda, false),
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &pool_ata, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("return_to_pool: fee_payer_not_signer CU={}", result.compute_units_consumed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// transfer_company_to_user tests
// ═══════════════════════════════════════════════════════════════════════════

mod transfer_company_to_user {
    use super::*;
    use zupy_pinocchio::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID;

    pub(super) fn ctoken_program_id() -> Pubkey {
        Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID)
    }

    /// Build the 8-account set for transfer_company_to_user (compressed Path B).
    ///
    /// Account layout matches `transfer_company_to_user.rs` and the Python client exactly.
    /// No ctoken_auth PDA — `cpi_compressed_transfer` uses only accounts[0..7].
    pub(super) fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        company_pda: &Pubkey,
        user_pda: &Pubkey,
        fee_payer: &Pubkey,
        ctoken_prog: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        vec![
            (*transfer_auth, make_system_account(10_000_000)),
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            (*mint, Account { lamports: 1_000_000, data: vec![0u8; 82], owner: token_2022_id(), executable: false, rent_epoch: 0 }),
            (*company_pda, make_program_account(vec![], 1_000_000)),  // [3] source
            (*user_pda, make_program_account(vec![], 1_000_000)),     // [4] dest
            (*fee_payer, make_system_account(10_000_000)),            // [5]
            make_program_stub(&system_program_id()),                   // [6]
            make_program_stub(ctoken_prog),                            // [7]
        ]
    }

    pub(super) fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        company_pda: &Pubkey,
        user_pda: &Pubkey,
        fee_payer: &Pubkey,
        ctoken_prog: &Pubkey,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(*transfer_auth, true),                    // [0]
            AccountMeta::new_readonly(*token_state_pda, false),        // [1]
            AccountMeta::new_readonly(*mint, false),                   // [2]
            AccountMeta::new_readonly(*company_pda, false),            // [3] source
            AccountMeta::new_readonly(*user_pda, false),               // [4] dest
            AccountMeta::new(*fee_payer, true),                        // [5]
            AccountMeta::new_readonly(system_program_id(), false),     // [6]
            AccountMeta::new_readonly(*ctoken_prog, false),            // [7]
        ]
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 0;
        let memo = build_string("zupy:v1:c2u:10:20");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.push(user_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_COMPANY_TO_USER, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("transfer_company_to_user: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_memo() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("bad-memo-no-colons");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.push(user_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_COMPANY_TO_USER, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_MEMO_FORMAT);
        println!("transfer_company_to_user: invalid_memo CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, true); // PAUSED

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_SYSTEM_PAUSED);
        println!("transfer_company_to_user: system_paused CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_transfer_authority() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        // Use wrong_auth as signer
        let metas = build_ix_metas(&wrong_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&wrong_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("transfer_company_to_user: wrong_authority CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_initialized() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, false, false); // NOT initialized

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_NOT_INITIALIZED);
        println!("transfer_company_to_user: not_initialized CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:c2u:10:20");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_COMPANY_TO_USER, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ]);

        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("transfer_company_to_user: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_token_program() {
        // Check 9: compressed_token_program must be Light cToken program.
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let wrong_ctoken_prog = Pubkey::new_unique(); // NOT Light cToken

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &user_pda, &fee_payer, &wrong_ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &user_pda, &fee_payer, &wrong_ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_TOKEN_PROGRAM);
        println!("transfer_company_to_user: invalid_token_program CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_company_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let wrong_company = Pubkey::new_unique();
        let (_, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &wrong_company, &user_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &wrong_company, &user_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("transfer_company_to_user: wrong_company_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_user_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (_, user_bump) = derive_user_pda(user_id);
        let wrong_user = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        // wrong_user in dest PDA position (index 4)
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &wrong_user, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &wrong_user, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("transfer_company_to_user: wrong_user_pda CU={}", result.compute_units_consumed);
    }

    // Note on full-flow test:
    // A complete compressed-to-compressed integration test requires the Light Protocol
    // cToken program loaded in Mollusk (via light-program-test or a mock). This is deferred
    // because the Light Protocol test infrastructure is not available in this environment.
    // All validation-path tests above verify that:
    // - Account count check updated to 9 (was 10) — ATAs removed, fee_payer + ctoken_prog added
    // - All error paths before the CPI work correctly with the new compressed account layout
    // Full CPI path is validated on devnet via manual transaction testing.
}

// ═══════════════════════════════════════════════════════════════════════════
// transfer_user_to_company tests
// ═══════════════════════════════════════════════════════════════════════════

mod transfer_user_to_company {
    use super::*;
    use zupy_pinocchio::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID;

    pub(super) fn ctoken_program_id() -> Pubkey {
        Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID)
    }

    fn derive_ctoken_authority(ctoken_prog: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[b"cpi_authority"], ctoken_prog).0
    }

    /// Build the 9-account set for transfer_user_to_company (compressed layout).
    pub(super) fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        user_pda: &Pubkey,
        company_pda: &Pubkey,
        fee_payer: &Pubkey,
        ctoken_prog: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        let ctoken_auth = derive_ctoken_authority(ctoken_prog);
        vec![
            (*transfer_auth, make_system_account(10_000_000)),
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            (*mint, Account { lamports: 1_000_000, data: vec![0u8; 82], owner: token_2022_id(), executable: false, rent_epoch: 0 }),
            (*user_pda, make_program_account(vec![], 1_000_000)),     // [3] source
            (*company_pda, make_program_account(vec![], 1_000_000)),  // [4] dest
            (*fee_payer, make_system_account(10_000_000)),            // [5]
            make_program_stub(&system_program_id()),                   // [6]
            make_program_stub(ctoken_prog),                            // [7]
            (ctoken_auth, make_system_account(1_000_000)),            // [8]
        ]
    }

    pub(super) fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        user_pda: &Pubkey,
        company_pda: &Pubkey,
        fee_payer: &Pubkey,
        ctoken_prog: &Pubkey,
    ) -> Vec<AccountMeta> {
        let ctoken_auth = derive_ctoken_authority(ctoken_prog);
        vec![
            AccountMeta::new(*transfer_auth, true),                    // [0]
            AccountMeta::new_readonly(*token_state_pda, false),        // [1]
            AccountMeta::new_readonly(*mint, false),                   // [2]
            AccountMeta::new_readonly(*user_pda, false),               // [3] source
            AccountMeta::new_readonly(*company_pda, false),            // [4] dest
            AccountMeta::new(*fee_payer, true),                        // [5]
            AccountMeta::new_readonly(system_program_id(), false),     // [6]
            AccountMeta::new_readonly(*ctoken_prog, false),            // [7]
            AccountMeta::new_readonly(ctoken_auth, false),             // [8]
        ]
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 0;
        let memo = build_string("zupy:v1:u2c:1:2");
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(user_bump);
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_USER_TO_COMPANY, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("transfer_user_to_company: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_memo() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

        let amount: u64 = 1_000_000;
        let memo = build_string("bad-memo-no-colons");
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(user_bump);
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_USER_TO_COMPANY, &payload);

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_MEMO_FORMAT);
        println!("transfer_user_to_company: invalid_memo CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, true); // PAUSED

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_SYSTEM_PAUSED);
        println!("transfer_user_to_company: system_paused CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_transfer_authority() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        // Use wrong_auth as signer
        let metas = build_ix_metas(&wrong_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&wrong_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("transfer_user_to_company: wrong_authority CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_initialized() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, false, false); // NOT initialized

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_NOT_INITIALIZED);
        println!("transfer_user_to_company: not_initialized CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:u2c:1:2");
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_USER_TO_COMPANY, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ]);

        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("transfer_user_to_company: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_token_program() {
        // Check 9: compressed_token_program must be Light cToken program.
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let wrong_ctoken_prog = Pubkey::new_unique(); // NOT Light cToken

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

        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &company_pda, &fee_payer, &wrong_ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &company_pda, &fee_payer, &wrong_ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_TOKEN_PROGRAM);
        println!("transfer_user_to_company: invalid_token_program CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_user_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let wrong_user = Pubkey::new_unique();
        let (_, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        // wrong_user in source PDA position (index 3)
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &wrong_user, &company_pda, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &wrong_user, &company_pda, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("transfer_user_to_company: wrong_user_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_company_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (_, company_bump) = derive_company_pda(company_id);
        let wrong_company = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = ctoken_program_id();

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

        // wrong_company in dest PDA position (index 4)
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &user_pda, &wrong_company, &fee_payer, &ctoken_prog);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &user_pda, &wrong_company, &fee_payer, &ctoken_prog);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("transfer_user_to_company: wrong_company_pda CU={}", result.compute_units_consumed);
    }

    // Note on full-flow test:
    // A complete compressed-to-compressed integration test requires the Light Protocol
    // cToken program loaded in Mollusk (via light-program-test or a mock). This is deferred
    // because the Light Protocol test infrastructure is not available in this environment.
    // All validation-path tests above verify that:
    // - Account count check updated to 9 (was 10) — ATAs removed, fee_payer + ctoken_prog added
    // - All error paths before the CPI work correctly with the new compressed account layout
    // Full CPI path is validated on devnet via manual transaction testing.
}

// ═══════════════════════════════════════════════════════════════════════════
// CU Benchmark: Validation-path measurement
// ═══════════════════════════════════════════════════════════════════════════

/// Measures CU consumed by each instruction's validation logic.
/// These tests pass all validation checks and fail at CPI (Token-2022 not loaded),
/// which gives us the CU cost of our optimized validation code.
#[test]
fn test_cu_benchmark_validation_paths() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();

    println!("\n═══ CU Benchmark: Hot-Path Transfer Validation ═══");

    // ── transfer_from_pool ──
    {
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);
        let recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:pool_transfer:1");
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

        let metas = transfer_from_pool::build_ix_metas(
            &transfer_auth, &token_state_pda, &mint, &pool_ata,
            &recipient, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = transfer_from_pool::build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &pool_ata, 10_000_000, &recipient, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  transfer_from_pool      CU: {:>6}  (validation + CPI attempt)", result.compute_units_consumed);
        assert!(
            result.compute_units_consumed <= CU_VALIDATION_THRESHOLD,
            "transfer_from_pool CU regression: {} > {}",
            result.compute_units_consumed, CU_VALIDATION_THRESHOLD,
        );
    }

    // ── return_to_pool (compressed layout — 11 accounts) ──
    {
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);
        let company_id: u64 = 42;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer_rtp = Pubkey::new_unique();
        let amount: u64 = 1_000_000;
        let memo = build_string("zupy:v1:return:42");
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.push(company_bump);
        payload.extend_from_slice(&memo);
        let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

        let metas = return_to_pool::build_ix_metas(
            &transfer_auth, &token_state_pda, &mint, &company_pda,
            &pool_ata, &fee_payer_rtp,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = return_to_pool::build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &company_pda, &pool_ata, &fee_payer_rtp,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  return_to_pool          CU: {:>6}  (validation + CPI attempt)", result.compute_units_consumed);
        assert!(
            result.compute_units_consumed <= CU_VALIDATION_THRESHOLD,
            "return_to_pool CU regression: {} > {}",
            result.compute_units_consumed, CU_VALIDATION_THRESHOLD,
        );
    }

    // ── transfer_company_to_user ──
    {
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);
        let company_id: u64 = 10;
        let user_id: u64 = 20;
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let fee_payer_c2u = Pubkey::new_unique();
        let ctoken_prog_c2u = transfer_company_to_user::ctoken_program_id();
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

        let metas = transfer_company_to_user::build_ix_metas(
            &transfer_auth, &token_state_pda, &mint, &company_pda,
            &user_pda, &fee_payer_c2u, &ctoken_prog_c2u,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = transfer_company_to_user::build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &company_pda, &user_pda, &fee_payer_c2u, &ctoken_prog_c2u,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  transfer_company_to_user CU: {:>6}  (validation + CPI attempt)", result.compute_units_consumed);
        assert!(
            result.compute_units_consumed <= CU_VALIDATION_THRESHOLD,
            "transfer_company_to_user CU regression: {} > {}",
            result.compute_units_consumed, CU_VALIDATION_THRESHOLD,
        );
    }

    // ── transfer_user_to_company ──
    {
        let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);
        let user_id: u64 = 1;
        let company_id: u64 = 2;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let fee_payer_u2c = Pubkey::new_unique();
        let ctoken_prog_u2c = transfer_user_to_company::ctoken_program_id();
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

        let metas = transfer_user_to_company::build_ix_metas(
            &transfer_auth, &token_state_pda, &mint, &user_pda,
            &company_pda, &fee_payer_u2c, &ctoken_prog_u2c,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = transfer_user_to_company::build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &company_pda, &fee_payer_u2c, &ctoken_prog_u2c,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  transfer_user_to_company CU: {:>6}  (validation + CPI attempt)", result.compute_units_consumed);
        assert!(
            result.compute_units_consumed <= CU_VALIDATION_THRESHOLD,
            "transfer_user_to_company CU regression: {} > {}",
            result.compute_units_consumed, CU_VALIDATION_THRESHOLD,
        );
    }

    println!("═══════════════════════════════════════════════════\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional error-path tests
// ═══════════════════════════════════════════════════════════════════════════

/// Tests bad memo format across transfer_from_pool (representative for all instructions
/// since they all call validate_memo_format before any instruction-specific logic).
#[test]
fn test_bad_memo_format_transfer_from_pool() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let fee_payer = Pubkey::new_unique();

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("bad-memo-no-colons"); // Invalid: not 4-part colon-separated
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

    let metas = transfer_from_pool::build_ix_metas(
        &transfer_auth, &token_state_pda, &mint, &pool_ata,
        &recipient, &fee_payer,
    );
    let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
    let accounts = transfer_from_pool::build_accounts(
        &transfer_auth, &token_state_pda, ts_data, &mint,
        &pool_ata, 10_000_000, &recipient, &fee_payer,
    );

    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_ix_custom_err(&result, ERR_INVALID_MEMO_FORMAT);
    println!("transfer_from_pool: bad_memo CU={}", result.compute_units_consumed);
}

/// Tests wrong token_program (not Token-2022) on return_to_pool.
/// token_program is at index 6 in the new 11-account layout.
#[test]
fn test_wrong_token_program_return_to_pool() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let pool_ata = Pubkey::new_unique();
    let company_id: u64 = 42;
    let (company_pda, company_bump) = derive_company_pda(company_id);
    let fee_payer = Pubkey::new_unique();

    let ts_data = make_transfer_token_state(&transfer_auth, &mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:return:42");
    let mut payload = Vec::new();
    payload.extend_from_slice(&company_id.to_le_bytes());
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.push(company_bump);
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_RETURN_TO_POOL, &payload);

    let wrong_token_program = Pubkey::new_unique();
    let ctoken_prog = ctoken_program_id();
    let ctoken_auth = derive_ctoken_authority();
    let spl_pda = derive_spl_interface_pda(&mint);
    let metas = vec![
        AccountMeta::new(transfer_auth, true),
        AccountMeta::new_readonly(token_state_pda, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(company_pda, false),
        AccountMeta::new(pool_ata, false),
        AccountMeta::new(fee_payer, true),
        AccountMeta::new_readonly(wrong_token_program, false), // idx 6: WRONG
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(ctoken_prog, false),
        AccountMeta::new_readonly(ctoken_auth, false),
        AccountMeta::new(spl_pda, false),
    ];
    let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

    let mut accounts = return_to_pool::build_accounts(
        &transfer_auth, &token_state_pda, ts_data, &mint,
        &company_pda, &pool_ata, &fee_payer,
    );
    // Replace token_program account (index 6) with wrong program
    accounts[6] = make_program_stub(&wrong_token_program);

    let result = mollusk.process_instruction(&instruction, &accounts);
    assert_ix_custom_err(&result, ERR_INVALID_TOKEN_PROGRAM);
    println!("return_to_pool: wrong_token_program CU={}", result.compute_units_consumed);
}

/// Tests wrong mint address (mint doesn't match token_state.mint) on transfer_from_pool.
#[test]
fn test_wrong_mint_transfer_from_pool() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();
    let transfer_auth = Pubkey::new_unique();
    let real_mint = Pubkey::new_unique();
    let wrong_mint = Pubkey::new_unique(); // WRONG mint
    let pool_ata = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let fee_payer = Pubkey::new_unique();

    // token_state stores real_mint, but we'll pass wrong_mint
    let ts_data = make_transfer_token_state(&transfer_auth, &real_mint, &pool_ata, bump, true, false);

    let amount: u64 = 1_000_000;
    let memo = build_string("zupy:v1:pool_transfer:1");
    let mut payload = Vec::new();
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&memo);
    let data = build_ix_data(&DISC_TRANSFER_FROM_POOL, &payload);

    // Build metas with wrong_mint
    let metas = transfer_from_pool::build_ix_metas(
        &transfer_auth, &token_state_pda, &wrong_mint, &pool_ata,
        &recipient, &fee_payer,
    );
    let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

    // Build accounts: mint account uses wrong_mint address but owned by Token-2022
    let mut accounts = transfer_from_pool::build_accounts(
        &transfer_auth, &token_state_pda, ts_data, &wrong_mint,
        &pool_ata, 10_000_000, &recipient, &fee_payer,
    );
    // Mint account (index 2) has wrong address
    accounts[2] = (wrong_mint, Account {
        lamports: 1_000_000,
        data: vec![0u8; 82],
        owner: token_2022_id(),
        executable: false,
        rent_epoch: 0,
    });

    let result = mollusk.process_instruction(&instruction, &accounts);
    // validate_transfer_common check 8: token_state.mint != mint.address() → InvalidMint
    assert_ix_custom_err(&result, ERR_INVALID_MINT);
    println!("transfer_from_pool: wrong_mint CU={}", result.compute_units_consumed);
}

// ═══════════════════════════════════════════════════════════════════════════
// withdraw_to_external tests
// ═══════════════════════════════════════════════════════════════════════════

const DISC_WITHDRAW_TO_EXTERNAL: [u8; 8] = [114, 198, 185, 119, 169, 163, 29, 251];

/// Max CU allowed for withdraw_to_external.
const CU_WITHDRAW_THRESHOLD: u64 = 15_000;

mod withdraw_to_external {
    use super::*;

    /// Build the 13-account set for withdraw_to_external.
    /// Accounts: transfer_auth, token_state, mint, user_pda, dest_wallet, dest_ata,
    ///           fee_payer, token_program, ata_program, system_program,
    ///           compressed_token_program, compressed_token_authority, spl_interface_pda
    pub(super) fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        user_pda: &Pubkey,
        dest_wallet: &Pubkey,
        dest_ata: &Pubkey,
        dest_ata_exists: bool,
        fee_payer: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        let dest_ata_account = if dest_ata_exists {
            Account {
                lamports: 1_000_000,
                data: make_token_account_data(mint, dest_wallet, 0),
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }
        } else {
            make_system_account(0) // empty — will be created by CPI
        };

        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);

        vec![
            // 0: transfer_authority (signer)
            (*transfer_auth, make_system_account(10_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (read)
            (*mint, Account {
                lamports: 1_000_000,
                data: vec![0u8; 82],
                owner: token_2022_id(),
                executable: false,
                rent_epoch: 0,
            }),
            // 3: user_pda (read)
            (*user_pda, make_program_account(vec![], 1_000_000)),
            // 4: dest_wallet (read)
            (*dest_wallet, make_system_account(1_000_000)),
            // 5: dest_ata (writable)
            (*dest_ata, dest_ata_account),
            // 6: fee_payer (writable, signer)
            (*fee_payer, make_system_account(10_000_000)),
            // 7: token_program (read)
            make_program_stub(&token_2022_id()),
            // 8: associated_token_program (read)
            make_program_stub(&ata_program_id()),
            // 9: system_program (read)
            make_program_stub(&system_program_id()),
            // 10: compressed_token_program (read)
            make_program_stub(&ctoken_program_id()),
            // 11: compressed_token_authority (read)
            (ctoken_auth, make_system_account(1_000_000)),
            // 12: spl_interface_pda (writable)
            (spl_pda, make_system_account(1_000_000)),
        ]
    }

    pub(super) fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        user_pda: &Pubkey,
        dest_wallet: &Pubkey,
        dest_ata: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<AccountMeta> {
        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(mint);

        vec![
            AccountMeta::new(*transfer_auth, true),                // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false),    // 1: read
            AccountMeta::new_readonly(*mint, false),               // 2: read
            AccountMeta::new_readonly(*user_pda, false),           // 3: read
            AccountMeta::new_readonly(*dest_wallet, false),        // 4: read
            AccountMeta::new(*dest_ata, false),                    // 5: writable
            AccountMeta::new(*fee_payer, true),                    // 6: writable+signer
            AccountMeta::new_readonly(token_2022_id(), false),     // 7
            AccountMeta::new_readonly(ata_program_id(), false),    // 8
            AccountMeta::new_readonly(system_program_id(), false), // 9
            AccountMeta::new_readonly(ctoken_program_id(), false), // 10
            AccountMeta::new_readonly(ctoken_auth, false),         // 11
            AccountMeta::new(spl_pda, false),                      // 12: writable
        ]
    }

    /// Build instruction payload for withdraw_to_external.
    /// Layout: amount(8) + user_id(8) + user_bump(1) + memo(4+len)
    fn build_payload(amount: u64, user_id: u64, user_bump: u8, memo: &str) -> Vec<u8> {
        let memo_bytes = build_string(memo);
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.push(user_bump);
        payload.extend_from_slice(&memo_bytes);
        payload
    }

    // ── Test: new external ATA flow (dest_ata does not exist) ──────────
    // NOTE: All CPI calls fail with UnsupportedProgramId in Mollusk.
    // This test verifies all validation passes before the first CPI
    // (cpi_create_ata_if_needed) is attempted.

    #[test]
    fn test_new_external_ata_flow() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 42;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let amount: u64 = 1_000_000;

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(amount, user_id, user_bump, "zupy:v1:withdraw:42");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        // dest_ata does NOT exist — ATA creation CPI attempted → UnsupportedProgramId
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::UnsupportedProgramId),
            "Expected UnsupportedProgramId (CPI layer), got {:?}",
            result.raw_result,
        );
        println!("withdraw_to_external: new_external_ata_flow CU={}", result.compute_units_consumed);
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
    }

    // ── Test: existing external ATA (dest_ata already exists) ──────────
    // dest_ata_exists=true → cpi_create_ata_if_needed short-circuits (data_len > 0, returns Ok())
    // → execution reaches cpi_decompress_to_spl → UnsupportedProgramId (Light CPI not in Mollusk)
    // The higher CU count vs test_new_external_ata_flow proves ATA creation was SKIPPED and
    // the code advanced past spl_pda derivation/validation to the decompress CPI.

    #[test]
    fn test_existing_external_ata() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 42;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let amount: u64 = 500_000;

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(amount, user_id, user_bump, "zupy:v1:withdraw:42");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        // dest_ata ALREADY exists — cpi_create_ata_if_needed returns Ok() immediately,
        // spl_pda is derived+validated, then cpi_decompress_to_spl fails → UnsupportedProgramId
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, true, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::UnsupportedProgramId),
            "Expected UnsupportedProgramId from cpi_decompress_to_spl (not ATA creation), got {:?}",
            result.raw_result,
        );
        // CU must exceed a meaningful threshold confirming execution advanced past
        // cpi_create_ata_if_needed short-circuit AND spl_pda derivation/validation,
        // reaching cpi_decompress_to_spl (which fails with UnsupportedProgramId).
        assert!(
            result.compute_units_consumed > 5_000,
            "CU {} too low — expected to reach cpi_decompress_to_spl (past ATA creation skip + spl_pda validation)",
            result.compute_units_consumed,
        );
        println!("withdraw_to_external: existing_external_ata CU={}", result.compute_units_consumed);
    }

    // ── Test: dest_ata exists with wrong mint ──────────────────────────
    // validate_destination_ata_if_exists reads the mint field from the ATA data
    // and returns InvalidMint if it doesn't match the instruction's mint.

    #[test]
    fn test_dest_ata_wrong_mint() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let wrong_mint = Pubkey::new_unique(); // ATA holds tokens of a DIFFERENT mint
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        // Build accounts with dest_ata existing but containing wrong_mint → InvalidMint.
        let mut accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );
        // Override dest_ata (idx 5): Token-2022-owned, data_len > 0, mint = wrong_mint
        accounts[5] = (dest_ata, Account {
            lamports: 1_000_000,
            data: make_token_account_data(&wrong_mint, &dest_wallet, 0),
            owner: token_2022_id(),
            executable: false,
            rent_epoch: 0,
        });

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_MINT);
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
        println!("withdraw_to_external: dest_ata_wrong_mint CU={}", result.compute_units_consumed);
    }

    // ── Test: dest_ata exists with wrong owner ─────────────────────────
    // validate_destination_ata_if_exists checks owner == Token-2022 before reading mint.
    // A non-Token-2022-owned account with data returns InvalidAuthority.

    #[test]
    fn test_dest_ata_wrong_owner() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        // Build accounts with dest_ata having data but NOT owned by Token-2022 → InvalidAuthority.
        let mut accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );
        // Override dest_ata (idx 5): system-owned with non-zero data → !owned_by(Token-2022)
        accounts[5] = (dest_ata, Account {
            lamports: 1_000_000,
            data: make_token_account_data(&mint, &dest_wallet, 0),
            owner: system_program_id(), // NOT Token-2022
            executable: false,
            rent_epoch: 0,
        });

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
        println!("withdraw_to_external: dest_ata_wrong_owner CU={}", result.compute_units_consumed);
    }

    // ── Invalid user PDA ──────────────────────────────────────────────

    #[test]
    fn test_invalid_user_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (_, user_bump) = derive_user_pda(user_id);
        let wrong_user = Pubkey::new_unique(); // NOT the real PDA
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &wrong_user, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &wrong_user, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        println!("withdraw_to_external: invalid_user_pda CU={}", result.compute_units_consumed);
    }

    // ── Wrong authority ─────────────────────────────────────────────────

    #[test]
    fn test_wrong_authority() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique(); // NOT the real authority
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        // Use wrong_auth as the signer instead of transfer_auth
        let mut metas = build_ix_metas(
            &wrong_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        metas[0] = AccountMeta::new(wrong_auth, true);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &wrong_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        println!("withdraw_to_external: wrong_authority CU={}", result.compute_units_consumed);
    }

    // ── Zero amount ─────────────────────────────────────────────────────

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(0, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_ZERO_AMOUNT);
        println!("withdraw_to_external: zero_amount CU={}", result.compute_units_consumed);
    }

    // ── System paused ───────────────────────────────────────────────────

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        // System is PAUSED
        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, true,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_SYSTEM_PAUSED);
        println!("withdraw_to_external: system_paused CU={}", result.compute_units_consumed);
    }

    // ── Invalid memo ────────────────────────────────────────────────────

    #[test]
    fn test_invalid_memo() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "bad-memo-format");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_MEMO_FORMAT);
        println!("withdraw_to_external: invalid_memo CU={}", result.compute_units_consumed);
    }

    // ── Wrong mint ──────────────────────────────────────────────────────

    #[test]
    fn test_wrong_mint() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let wrong_mint = Pubkey::new_unique(); // different from token_state.mint
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        // Use wrong_mint in both metas and accounts so spl_pda derivations match.
        // ts_data stores real_mint, so validate_transfer_common detects
        // token_state.mint != wrong_mint → InvalidMint.
        let metas = build_ix_metas(
            &transfer_auth, &token_state_pda, &wrong_mint,
            &user_pda, &dest_wallet, &dest_ata, &fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &wrong_mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_MINT);
        println!("withdraw_to_external: wrong_mint CU={}", result.compute_units_consumed);
    }

    // ── Not enough accounts ─────────────────────────────────────────────

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let user_id: u64 = 1;
        let payload = build_payload(1_000_000, user_id, 0, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        // Only pass 5 accounts (need 13)
        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ]);

        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("withdraw_to_external: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    // ── Test: fee_payer is not a signer (N2 fix) ────────────────────────

    #[test]
    fn test_fee_payer_not_signer() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(&mint);
        // fee_payer at idx 6 declared as non-signer → triggers fee_payer.is_signer() check
        let metas = vec![
            AccountMeta::new(transfer_auth, true),                 // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),     // 1: read
            AccountMeta::new_readonly(mint, false),                // 2: read
            AccountMeta::new_readonly(user_pda, false),            // 3: read
            AccountMeta::new_readonly(dest_wallet, false),         // 4: read
            AccountMeta::new(dest_ata, false),                     // 5: writable
            AccountMeta::new(fee_payer, false),                    // 6: NOT signer
            AccountMeta::new_readonly(token_2022_id(), false),     // 7
            AccountMeta::new_readonly(ata_program_id(), false),    // 8
            AccountMeta::new_readonly(system_program_id(), false), // 9
            AccountMeta::new_readonly(ctoken_program_id(), false), // 10
            AccountMeta::new_readonly(ctoken_auth, false),         // 11
            AccountMeta::new(spl_pda, false),                      // 12
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_AUTHORITY);
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
        println!("withdraw_to_external: fee_payer_not_signer CU={}", result.compute_units_consumed);
    }

    // ── Test: wrong compressed_token_program (N2 fix) ────────────────────

    #[test]
    fn test_wrong_compressed_token_program() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let wrong_ctoken_prog = Pubkey::new_unique(); // NOT LIGHT_COMPRESSED_TOKEN_PROGRAM_ID

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let ctoken_auth = derive_ctoken_authority();
        let spl_pda = derive_spl_interface_pda(&mint);
        let metas = vec![
            AccountMeta::new(transfer_auth, true),                 // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),     // 1: read
            AccountMeta::new_readonly(mint, false),                // 2: read
            AccountMeta::new_readonly(user_pda, false),            // 3: read
            AccountMeta::new_readonly(dest_wallet, false),         // 4: read
            AccountMeta::new(dest_ata, false),                     // 5: writable
            AccountMeta::new(fee_payer, true),                     // 6: signer
            AccountMeta::new_readonly(token_2022_id(), false),     // 7
            AccountMeta::new_readonly(ata_program_id(), false),    // 8
            AccountMeta::new_readonly(system_program_id(), false), // 9
            AccountMeta::new_readonly(wrong_ctoken_prog, false),   // 10: WRONG ctoken program
            AccountMeta::new_readonly(ctoken_auth, false),         // 11
            AccountMeta::new(spl_pda, false),                      // 12
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        let mut accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, false, &fee_payer,
        );
        accounts[10] = make_program_stub(&wrong_ctoken_prog); // replace ctoken program at idx 10

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::IncorrectProgramId),
            "Expected IncorrectProgramId for wrong ctoken program, got {:?}",
            result.raw_result,
        );
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
        println!("withdraw_to_external: wrong_compressed_token_program CU={}", result.compute_units_consumed);
    }

    // ── Test: wrong spl_interface_pda (N2 fix) ──────────────────────────

    #[test]
    fn test_wrong_spl_interface_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pool_ata = Pubkey::new_unique();
        let user_id: u64 = 1;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let dest_wallet = Pubkey::new_unique();
        let dest_ata = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let wrong_spl_pda = Pubkey::new_unique(); // NOT derive_spl_interface_pda(mint)

        let ts_data = make_transfer_token_state(
            &transfer_auth, &mint, &pool_ata, bump, true, false,
        );

        let payload = build_payload(1_000_000, user_id, user_bump, "zupy:v1:withdraw:1");
        let data = build_ix_data(&DISC_WITHDRAW_TO_EXTERNAL, &payload);

        let ctoken_auth = derive_ctoken_authority();
        let metas = vec![
            AccountMeta::new(transfer_auth, true),                 // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),     // 1: read
            AccountMeta::new_readonly(mint, false),                // 2: read
            AccountMeta::new_readonly(user_pda, false),            // 3: read
            AccountMeta::new_readonly(dest_wallet, false),         // 4: read
            AccountMeta::new(dest_ata, false),                     // 5: writable
            AccountMeta::new(fee_payer, true),                     // 6: signer
            AccountMeta::new_readonly(token_2022_id(), false),     // 7
            AccountMeta::new_readonly(ata_program_id(), false),    // 8
            AccountMeta::new_readonly(system_program_id(), false), // 9
            AccountMeta::new_readonly(ctoken_program_id(), false), // 10: correct ctoken program
            AccountMeta::new_readonly(ctoken_auth, false),         // 11
            AccountMeta::new(wrong_spl_pda, false),                // 12: WRONG spl_interface_pda
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        // dest_ata_exists=true so cpi_create_ata_if_needed short-circuits → code reaches validate_pda
        let mut accounts = build_accounts(
            &transfer_auth, &token_state_pda, ts_data, &mint,
            &user_pda, &dest_wallet, &dest_ata, true, &fee_payer,
        );
        accounts[12] = (wrong_spl_pda, make_system_account(1_000_000)); // replace spl_pda at idx 12

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, ERR_INVALID_PDA);
        assert!(
            result.compute_units_consumed <= CU_WITHDRAW_THRESHOLD,
            "CU {} exceeds threshold {}",
            result.compute_units_consumed, CU_WITHDRAW_THRESHOLD,
        );
        println!("withdraw_to_external: wrong_spl_interface_pda CU={}", result.compute_units_consumed);
    }
}
