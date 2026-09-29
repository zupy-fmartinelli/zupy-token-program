//! Mollusk integration tests for Split Transfer + Burns.
//!
//! Tests all 3 instructions:
//!   - execute_split_transfer (9+ accounts, compressed token CPIs)
//!   - burn_tokens (6 accounts, regular invoke)
//!   - burn_from_company_pda (6 accounts, invoke_signed)
//!
//! Requires `cargo build-sbf` before running:
//!   cargo build-sbf && cargo test --test test_split_burns -- --nocapture

mod helpers;
use helpers::*;

use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use zupy_token_program::state::token_state::TOKEN_STATE_SIZE;

// ── Instruction discriminators ─────────────────────────────────────────────
const DISC_EXECUTE_SPLIT_TRANSFER: [u8; 8] = [51, 254, 61, 214, 234, 138, 101, 214];
const DISC_BURN_TOKENS: [u8; 8] = [76, 15, 51, 254, 229, 215, 121, 66];
const DISC_BURN_FROM_COMPANY_PDA: [u8; 8] = [43, 207, 204, 77, 74, 93, 165, 34];

// ═══════════════════════════════════════════════════════════════════════════
// execute_split_transfer tests
// ═══════════════════════════════════════════════════════════════════════════

/// execute_split_transfer — Compressed Token Layout (9+ accounts)
///
/// Account layout (new — replaces old 10-account ATA layout):
///   [0] transfer_authority (signer)
///   [1] token_state (read)
///   [2] mint (read)
///   [3] user_pda (read) — source / PDA signer
///   [4] company_pda (read) — destination for Transfer 1
///   [5] incentive_pool_pda (read) — destination for Transfer 2
///   [6] fee_payer (writable, signer)
///   [7] system_program (read)
///   [8] compressed_token_program (read) — Light cToken
///   [9+] V1 cToken CPI accounts (fee_payer, authority = user_pda, …) — story 3.21
mod execute_split_transfer {
    use super::*;

    fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        user_pda: &Pubkey,
        company_pda: &Pubkey,
        incentive_pool_pda: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        vec![
            // 0: transfer_authority (signer)
            (*transfer_auth, make_system_account(1_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (read)
            (*mint, make_token_owned_account(vec![0u8; 82])),
            // 3: user_pda (read)
            (*user_pda, make_program_account(vec![], 1_000_000)),
            // 4: company_pda (read)
            (*company_pda, make_program_account(vec![], 1_000_000)),
            // 5: incentive_pool_pda (read)
            (*incentive_pool_pda, make_program_account(vec![], 1_000_000)),
            // 6: fee_payer (writable, signer)
            (*fee_payer, make_system_account(10_000_000)),
            // 7: system_program (read)
            make_program_stub(&system_program_id()),
            // 8: compressed_token_program (read) — Light cToken
            make_program_stub(&ctoken_program_id()),
        ]
    }

    fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        user_pda: &Pubkey,
        company_pda: &Pubkey,
        incentive_pool_pda: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(*transfer_auth, true),               // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false),   // 1
            AccountMeta::new_readonly(*mint, false),               // 2
            AccountMeta::new_readonly(*user_pda, false),           // 3
            AccountMeta::new_readonly(*company_pda, false),        // 4
            AccountMeta::new_readonly(*incentive_pool_pda, false), // 5
            AccountMeta::new(*fee_payer, true),                    // 6: writable signer
            AccountMeta::new_readonly(system_program_id(), false), // 7
            AccountMeta::new_readonly(ctoken_program_id(), false), // 8
        ]
    }

    fn build_payload(
        user_id: u64, company_id: u64, company_amount: u64, pool_amount: u64,
        user_bump: u8, company_bump: u8, incentive_bump: u8,
        op_type: &str,
    ) -> Vec<u8> {
        // Burn-free explicit-amount layout (AD-A1): two u64 legs replace z_total.
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&company_amount.to_le_bytes());
        payload.extend_from_slice(&pool_amount.to_le_bytes());
        payload.push(user_bump);
        payload.push(company_bump);
        payload.push(incentive_bump);
        payload.extend_from_slice(&build_string(op_type));
        payload
    }

    /// Common test state for execute_split_transfer tests.
    struct TestSetup {
        transfer_auth: Pubkey,
        token_state_pda: Pubkey,
        bump: u8,
        mint: Pubkey,
        user_id: u64,
        company_id: u64,
        user_pda: Pubkey,
        user_bump: u8,
        company_pda: Pubkey,
        company_bump: u8,
        incentive_pool_pda: Pubkey,
        incentive_bump: u8,
        fee_payer: Pubkey,
    }

    fn setup() -> TestSetup {
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let user_id: u64 = 42;
        let company_id: u64 = 99;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (incentive_pool_pda, incentive_bump) = derive_incentive_pool_pda();
        let fee_payer = Pubkey::new_unique();

        TestSetup {
            transfer_auth, token_state_pda, bump, mint,
            user_id, company_id, user_pda, user_bump, company_pda, company_bump,
            incentive_pool_pda, incentive_bump, fee_payer,
        }
    }

    // ── Error path tests ────────────────────────────────────────────────

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let payload = build_payload(42, 99, 1_000_000, 0, 0, 0, 0, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new(Pubkey::new_unique(), true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
        ]);
        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("split_transfer: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 0, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6012); // ZeroAmount
        println!("split_transfer: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_invalid_operation_type() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "invalid_type");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6028); // InvalidOperationType
        println!("split_transfer: invalid_operation_type CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_initialized() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, false, false, // NOT initialized
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6010); // NotInitialized
        println!("split_transfer: not_initialized CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, true, // PAUSED
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6018); // SystemPaused
        println!("split_transfer: system_paused CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_authority() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_auth = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &wrong_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &wrong_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("split_transfer: wrong_authority CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_user_pda() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_user = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &wrong_user, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &wrong_user, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("split_transfer: wrong_user_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_company_pda() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_company = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &wrong_company, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &wrong_company, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("split_transfer: wrong_company_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_incentive_pool_pda() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_pool = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &wrong_pool, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &wrong_pool, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("split_transfer: wrong_incentive_pool_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_token_state_owner() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        accounts[1].1.owner = Pubkey::new_unique(); // wrong owner

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("split_transfer: wrong_token_state_owner CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_bad_token_state_pda() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_pda = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &wrong_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &wrong_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("split_transfer: bad_token_state_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_short_data_len() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = vec![0u8; TOKEN_STATE_SIZE - 1]; // too short

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::InvalidAccountData),
            "Expected InvalidAccountData for short token_state, got {:?}",
            result.raw_result,
        );
        println!("split_transfer: short_data_len CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_mint() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_mint = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &wrong_mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &wrong_mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6011); // InvalidMint
        println!("split_transfer: wrong_mint CU={}", result.compute_units_consumed);
    }

    /// AC: compressed_token_program must be the Light cToken program (InvalidTokenProgram).
    #[test]
    fn test_wrong_compressed_token_program() {
        let mollusk = setup_mollusk();
        let s = setup();
        let wrong_ctoken = Pubkey::new_unique();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);

        // Override accounts[8] with a wrong ctoken program
        let mut metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        metas[8] = AccountMeta::new_readonly(wrong_ctoken, false);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);

        let mut accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        accounts[8] = make_program_stub(&wrong_ctoken);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6025); // InvalidTokenProgram
        println!("split_transfer: wrong_compressed_token_program CU={}", result.compute_units_consumed);
    }

    // ── V1 TRANSFER with proof (story 3.21) ─────────────────────────────
    //
    // Since 3.21 the split forwards ONE cToken V1 TRANSFER (with validity
    // proof) built by the backend, appended after `operation_type`; the V1
    // CPI accounts start at index 9. Basic Mollusk does not load the cToken,
    // so "success" here means: every check passed and the CPI was attempted
    // (`UnsupportedProgramId`). The real cToken/Light binaries run in
    // `tests/test_mainnet_fork.rs`.

    fn split_ix(
        s: &TestSetup,
        ts_data: Vec<u8>,
        company_amount: u64,
        pool_amount: u64,
        v1: &[u8],
        cpi_authority: &Pubkey,
    ) -> (Instruction, Vec<(Pubkey, Account)>) {
        let mut payload = build_payload(
            s.user_id, s.company_id, company_amount, pool_amount,
            s.user_bump, s.company_bump, s.incentive_bump, "z_direct",
        );
        payload.extend_from_slice(v1);
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);
        let mut metas = build_ix_metas(
            &s.transfer_auth, &s.token_state_pda, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        metas.extend(v1_cpi_tail_metas(&s.fee_payer, cpi_authority));
        let mut accounts = build_accounts(
            &s.transfer_auth, &s.token_state_pda, ts_data, &s.mint,
            &s.user_pda, &s.company_pda, &s.incentive_pool_pda, &s.fee_payer,
        );
        if !accounts.iter().any(|(k, _)| k == cpi_authority) {
            accounts.push((*cpi_authority, make_system_account(0)));
        }
        (Instruction::new_with_bytes(program_id(), &data, metas), accounts)
    }

    fn split_state(s: &TestSetup) -> Vec<u8> {
        make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        )
    }

    /// Valid 3-output payload: 1_000_000 leaf → company 800_000, pool 40_000, change 160_000.
    fn v1_split(s: &TestSetup, leaf: u64, company: u64, pool: u64) -> Vec<u8> {
        let mut outs = vec![(s.company_pda, company, 0u8)];
        if pool > 0 {
            outs.push((s.incentive_pool_pda, pool, 0));
        }
        if leaf > company + pool {
            outs.push((s.user_pda, leaf - company - pool, 0));
        }
        build_v1_transfer(&s.mint, Some([9u8; 128]), &[V1Input::with_proof(leaf)], &outs)
    }

    #[test]
    fn test_full_split_flow_reaches_cpi_stage() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 40_000);
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        // Every check passed; the only thing left is the cToken CPI (not loaded here).
        assert_eq!(result.raw_result, Err(InstructionError::UnsupportedProgramId));
        println!("split_transfer: full V1 flow CU={} (reaches cToken CPI)", result.compute_units_consumed);
    }

    #[test]
    fn test_pool_zero_skips_pool_output_and_reaches_cpi() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 0);
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 0, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_eq!(result.raw_result, Err(InstructionError::UnsupportedProgramId));
    }

    /// The 396df04 / 3.17 adapter sends only the header. It must fail closed,
    /// before any CPI (it used to reach the disc=3 CPI and die with 18063).
    #[test]
    fn test_header_only_payload_fails_before_cpi() {
        let mollusk = setup_mollusk();
        let s = setup();
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &[], &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_eq!(result.raw_result, Err(InstructionError::InvalidInstructionData));
    }

    #[test]
    fn test_insufficient_balance_in_leaf() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = build_v1_transfer(
            &s.mint, Some([9u8; 128]), &[V1Input::with_proof(500_000)],
            &[(s.company_pda, 800_000, 0), (s.incentive_pool_pda, 40_000, 0)],
        );
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6004); // InsufficientBalance
    }

    #[test]
    fn test_zero_company_leg_rejected() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 0, 40_000);
        let (ix, accounts) = split_ix(&s, split_state(&s), 0, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6012); // ZeroAmount
    }

    #[test]
    fn test_legs_overflow_rejected() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 40_000);
        let (ix, accounts) = split_ix(&s, split_state(&s), u64::MAX, 1, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6029); // SplitCalculationError
    }

    #[test]
    fn test_payload_pool_amount_disagrees_with_header() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 50_000); // header says 40_000
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6005); // InvalidAmount
    }

    #[test]
    fn test_payload_sends_company_leg_elsewhere() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = build_v1_transfer(
            &s.mint, Some([9u8; 128]), &[V1Input::with_proof(840_000)],
            &[(Pubkey::new_unique(), 800_000, 0), (s.incentive_pool_pda, 40_000, 0)],
        );
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
    }

    #[test]
    fn test_payload_with_foreign_mint() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = build_v1_transfer(
            &Pubkey::new_unique(), Some([9u8; 128]), &[V1Input::with_proof(840_000)],
            &[(s.company_pda, 800_000, 0), (s.incentive_pool_pda, 40_000, 0)],
        );
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6011); // InvalidMint
    }

    /// The V1 authority (who owns the input leaves for the cToken) must be the
    /// user PDA the program signs for — never a company or anyone else.
    #[test]
    fn test_cpi_authority_must_be_user_pda() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 40_000);
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.company_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
    }

    #[test]
    fn test_missing_cpi_accounts() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 40_000);
        let (mut ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        ix.accounts.truncate(9); // no V1 CPI tail
        let result = mollusk.process_instruction(&ix, &accounts);
        assert_ix_not_enough_keys(&result);
    }

    // ── CU benchmark (validation + V1 payload check, up to the CPI) ──────

    #[test]
    fn test_cu_benchmark_compressed_validation_path() {
        let mollusk = setup_mollusk();
        let s = setup();
        let v1 = v1_split(&s, 1_000_000, 800_000, 40_000);
        let (ix, accounts) = split_ix(&s, split_state(&s), 800_000, 40_000, &v1, &s.user_pda);
        let result = mollusk.process_instruction(&ix, &accounts);
        // The full CPI (cToken + Light system + proof verification) is measured
        // with the real mainnet binaries in tests/test_mainnet_fork.rs.
        println!(
            "  execute_split_transfer (V1)        CU: {:>6}  (validation + payload check, up to the CPI)",
            result.compute_units_consumed
        );
        assert_eq!(result.raw_result, Err(InstructionError::UnsupportedProgramId));
        assert!(
            result.compute_units_consumed <= 30_000,
            "execute_split_transfer validation-path CU {} exceeds 30,000 threshold",
            result.compute_units_consumed,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// burn_tokens tests
// ═══════════════════════════════════════════════════════════════════════════

mod burn_tokens {
    use super::*;

    fn build_accounts(
        authority: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        token_account: &Pubkey,
        token_account_owner: &Pubkey,
        balance: u64,
    ) -> Vec<(Pubkey, Account)> {
        vec![
            // 0: authority (signer) -- treasury
            (*authority, make_system_account(1_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (writable)
            (*mint, make_token_owned_account(vec![0u8; 82])),
            // 3: token_account (writable)
            (*token_account, make_token_owned_account(make_token_account_data(mint, token_account_owner, balance))),
            // 4: token_account_owner (signer)
            (*token_account_owner, make_system_account(1_000_000)),
            // 5: token_program (read)
            make_program_stub(&token_2022_id()),
        ]
    }

    fn build_ix_metas(
        authority: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        token_account: &Pubkey,
        token_account_owner: &Pubkey,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(*authority, true),    // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false), // 1
            AccountMeta::new(*mint, false),                 // 2: writable
            AccountMeta::new(*token_account, false),        // 3: writable
            AccountMeta::new_readonly(*token_account_owner, true), // 4: signer
            AccountMeta::new_readonly(token_2022_id(), false), // 5
        ]
    }

    fn build_payload(amount: u64, memo: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&build_string(memo));
        payload
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new_readonly(Pubkey::new_unique(), true),
        ]);
        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("burn_tokens: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(0, "zupy:v1:burn:123"); // ZERO
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6012); // ZeroAmount
        println!("burn_tokens: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_bad_memo() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "bad_format");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6009); // InvalidMemoFormat
        println!("burn_tokens: bad_memo CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_not_initialized() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, false, false, // NOT initialized
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6010); // NotInitialized
        println!("burn_tokens: not_initialized CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_treasury() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let wrong_treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&wrong_treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&wrong_treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_tokens: wrong_treasury CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_token_account_owner_not_signer() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let mut metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        metas[4] = AccountMeta::new_readonly(token_account_owner, false); // NOT signer
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_tokens: owner_not_signer CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_insufficient_balance() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(10_000_000, "zupy:v1:burn:123"); // more than balance
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6004); // InsufficientBalance
        println!("burn_tokens: insufficient_balance CU={}", result.compute_units_consumed);
    }

    // ── Additional error path tests (Review MAJOR-1) ──────────────────

    #[test]
    fn test_wrong_token_state_owner() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);
        // Override token_state owner to wrong program
        accounts[1].1.owner = Pubkey::new_unique();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_tokens: wrong_token_state_owner CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_bad_token_state_pda() {
        let mollusk = setup_mollusk();
        let (_, bump) = derive_token_state_pda();
        let wrong_pda = Pubkey::new_unique();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &wrong_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &wrong_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("burn_tokens: bad_token_state_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_short_data_len() {
        let mollusk = setup_mollusk();
        let (token_state_pda, _) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = vec![0u8; TOKEN_STATE_SIZE - 1]; // too short

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::InvalidAccountData),
            "Expected InvalidAccountData for short token_state, got {:?}",
            result.raw_result,
        );
        println!("burn_tokens: short_data_len CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_mint() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let wrong_mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        // token_state stores `mint` as its mint
        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        // Pass wrong_mint as the mint account
        let metas = build_ix_metas(&treasury, &token_state_pda, &wrong_mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &wrong_mint, &token_account, &token_account_owner, 1_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6011); // InvalidMint
        println!("burn_tokens: wrong_mint CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_token_program() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let wrong_tp = Pubkey::new_unique();
        let mut metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        metas[5] = AccountMeta::new_readonly(wrong_tp, false);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 1_000_000);
        accounts[5] = make_program_stub(&wrong_tp);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6025); // InvalidTokenProgram
        println!("burn_tokens: wrong_token_program CU={}", result.compute_units_consumed);
    }

    // ── CU Benchmark ───────────────────────────────────────────────────

    #[test]
    fn test_cu_benchmark_validation_path() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(1_000_000, "zupy:v1:burn:123");
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);
        let metas = build_ix_metas(&treasury, &token_state_pda, &mint, &token_account, &token_account_owner);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&treasury, &token_state_pda, ts_data, &mint, &token_account, &token_account_owner, 10_000_000);

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!(
            "  burn_tokens             CU: {:>6}  (validation + CPI attempt)",
            result.compute_units_consumed
        );
        assert!(
            result.compute_units_consumed <= 10_000,
            "burn_tokens CU {} exceeds 10,000 threshold",
            result.compute_units_consumed,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// burn_from_company_pda tests (compressed layout — 7 accounts minimum)
// ═══════════════════════════════════════════════════════════════════════════

mod burn_from_company_pda {
    use super::*;
    use zupy_token_program::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID;

    fn ctoken_program_id() -> Pubkey {
        Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID)
    }

    /// Build the 7-account set for burn_from_company_pda (compressed layout).
    fn build_accounts(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        token_state_data: Vec<u8>,
        mint: &Pubkey,
        company_pda: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<(Pubkey, Account)> {
        let ctoken_prog = ctoken_program_id();
        vec![
            // 0: transfer_authority (signer)
            (*transfer_auth, make_system_account(1_000_000)),
            // 1: token_state (read)
            (*token_state_pda, make_program_account(token_state_data, 1_000_000)),
            // 2: mint (writable)
            (*mint, make_token_owned_account(vec![0u8; 82])),
            // 3: company_pda (read)
            (*company_pda, make_program_account(vec![], 1_000_000)),
            // 4: fee_payer (writable, signer)
            (*fee_payer, make_system_account(10_000_000)),
            // 5: system_program (read)
            make_program_stub(&system_program_id()),
            // 6: compressed_token_program (read)
            make_program_stub(&ctoken_prog),
        ]
    }

    fn build_ix_metas(
        transfer_auth: &Pubkey,
        token_state_pda: &Pubkey,
        mint: &Pubkey,
        company_pda: &Pubkey,
        fee_payer: &Pubkey,
    ) -> Vec<AccountMeta> {
        let ctoken_prog = ctoken_program_id();
        vec![
            AccountMeta::new_readonly(*transfer_auth, true),            // 0: signer
            AccountMeta::new_readonly(*token_state_pda, false),          // 1: read
            AccountMeta::new(*mint, false),                              // 2: writable
            AccountMeta::new_readonly(*company_pda, false),              // 3: read
            AccountMeta::new(*fee_payer, true),                          // 4: writable, signer
            AccountMeta::new_readonly(system_program_id(), false),       // 5: system_program
            AccountMeta::new_readonly(ctoken_prog, false),               // 6: ctoken program
        ]
    }

    fn build_payload(company_id: u64, amount: u64, memo: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&build_string(memo));
        payload
    }

    #[test]
    fn test_not_enough_accounts() {
        let mollusk = setup_mollusk();
        let payload = build_payload(42, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);

        let instruction = Instruction::new_with_bytes(program_id(), &data, vec![
            AccountMeta::new_readonly(Pubkey::new_unique(), true),
        ]);
        let accounts: Vec<(Pubkey, Account)> = instruction.accounts.iter().map(|meta| {
            (meta.pubkey, make_system_account(1_000_000))
        }).collect();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_not_enough_keys(&result);
        println!("burn_from_company_pda: not_enough_accounts CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_zero_amount() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 0, "zupy:v1:burn:42"); // ZERO
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6012); // ZeroAmount
        println!("burn_from_company_pda: zero_amount CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_bad_memo() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "bad_format");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6009); // InvalidMemoFormat
        println!("burn_from_company_pda: bad_memo CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_system_paused() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, true, // PAUSED
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6018); // SystemPaused
        println!("burn_from_company_pda: system_paused CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_authority() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let wrong_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&wrong_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&wrong_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_from_company_pda: wrong_authority CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_company_pda() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let wrong_company = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &wrong_company, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &wrong_company, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("burn_from_company_pda: wrong_company_pda CU={}", result.compute_units_consumed);
    }

    // ── Additional error path tests ──────────────────────────────────────

    #[test]
    fn test_wrong_token_state_owner() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);
        // Override token_state owner to wrong program
        accounts[1].1.owner = Pubkey::new_unique();

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_from_company_pda: wrong_token_state_owner CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_bad_token_state_pda() {
        let mollusk = setup_mollusk();
        let (_, bump) = derive_token_state_pda();
        let wrong_pda = Pubkey::new_unique();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &wrong_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &wrong_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6007); // InvalidPDA
        println!("burn_from_company_pda: bad_token_state_pda CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_short_data_len() {
        let mollusk = setup_mollusk();
        let (token_state_pda, _) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = vec![0u8; TOKEN_STATE_SIZE - 1]; // too short

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::InvalidAccountData),
            "Expected InvalidAccountData for short token_state, got {:?}",
            result.raw_result,
        );
        println!("burn_from_company_pda: short_data_len CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_fee_payer_not_signer() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        // fee_payer at index 4 must NOT be a signer to trigger InvalidAuthority
        let mut metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        metas[4] = AccountMeta::new_readonly(fee_payer, false);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_ix_custom_err(&result, 6000); // InvalidAuthority
        println!("burn_from_company_pda: fee_payer_not_signer CU={}", result.compute_units_consumed);
    }

    #[test]
    fn test_wrong_compressed_token_program() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let wrong_ctoken = Pubkey::new_unique();
        let mut metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        metas[6] = AccountMeta::new_readonly(wrong_ctoken, false);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let mut accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);
        accounts[6] = make_program_stub(&wrong_ctoken);

        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(
            result.raw_result,
            Err(InstructionError::IncorrectProgramId),
            "Expected IncorrectProgramId for wrong ctoken program, got {:?}",
            result.raw_result,
        );
        println!("burn_from_company_pda: wrong_compressed_token_program CU={}", result.compute_units_consumed);
    }

    // ── CU Benchmark ───────────────────────────────────────────────────

    #[test]
    fn test_cu_benchmark_validation_path() {
        let mollusk = setup_mollusk();
        let (token_state_pda, bump) = derive_token_state_pda();
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let payload = build_payload(company_id, 1_000_000, "zupy:v1:burn:42");
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);
        let metas = build_ix_metas(&transfer_auth, &token_state_pda, &mint, &company_pda, &fee_payer);
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = build_accounts(&transfer_auth, &token_state_pda, ts_data, &mint, &company_pda, &fee_payer);

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!(
            "  burn_from_company_pda   CU: {:>6}  (validation + CPI attempt)",
            result.compute_units_consumed
        );
        assert!(
            result.compute_units_consumed <= 10_000,
            "burn_from_company_pda CU {} exceeds 10,000 threshold",
            result.compute_units_consumed,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CU Benchmark: Consolidated report
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_cu_benchmark_all_split_burn_instructions() {
    let mollusk = setup_mollusk();
    let (token_state_pda, bump) = derive_token_state_pda();

    println!("\n═══ CU Benchmark: Split Transfer + Burns ═══");

    // ── execute_split_transfer (9 accounts + V1 CPI tail, story 3.21) ──
    {
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let user_id: u64 = 42;
        let company_id: u64 = 99;
        let (user_pda, user_bump) = derive_user_pda(user_id);
        let (company_pda, company_bump) = derive_company_pda(company_id);
        let (incentive_pool_pda, incentive_bump) = derive_incentive_pool_pda();
        let fee_payer = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &incentive_pool_pda, bump, true, false,
        );

        // Header (explicit legs) + V1 TRANSFER with proof (story 3.21).
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&800_000u64.to_le_bytes()); // company_amount
        payload.extend_from_slice(&40_000u64.to_le_bytes()); // pool_amount
        payload.push(user_bump);
        payload.push(company_bump);
        payload.push(incentive_bump);
        payload.extend_from_slice(&build_string("mixed_payment"));
        payload.extend_from_slice(&build_v1_transfer(
            &mint, Some([9u8; 128]), &[V1Input::with_proof(1_000_000)],
            &[(company_pda, 800_000, 0), (incentive_pool_pda, 40_000, 0), (user_pda, 160_000, 0)],
        ));
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);

        let mut metas = vec![
            AccountMeta::new(transfer_auth, true),                     // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),         // 1
            AccountMeta::new_readonly(mint, false),                    // 2
            AccountMeta::new_readonly(user_pda, false),                // 3
            AccountMeta::new_readonly(company_pda, false),             // 4
            AccountMeta::new_readonly(incentive_pool_pda, false),      // 5
            AccountMeta::new(fee_payer, true),                         // 6: fee_payer (writable signer)
            AccountMeta::new_readonly(system_program_id(), false),     // 7
            AccountMeta::new_readonly(ctoken_program_id(), false),     // 8: Light cToken
        ];
        metas.extend(v1_cpi_tail_metas(&fee_payer, &user_pda)); // 9+: V1 CPI accounts
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = vec![
            (transfer_auth, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 82])),
            (user_pda, make_program_account(vec![], 1_000_000)),
            (company_pda, make_program_account(vec![], 1_000_000)),
            (incentive_pool_pda, make_program_account(vec![], 1_000_000)),
            (fee_payer, make_system_account(10_000_000)),
            make_program_stub(&system_program_id()),
            make_program_stub(&ctoken_program_id()),
        ];

        // Reaches the V1 cToken CPI (not loaded in basic Mollusk) — measures CU
        // through all on-chain validation + payload check + CPI dispatch.
        let result = mollusk.process_instruction(&instruction, &accounts);
        assert_eq!(result.raw_result, Err(InstructionError::UnsupportedProgramId));
        println!("  execute_split_transfer  CU: {:>6}  (validation + CPI attempt, target ≤30,000)", result.compute_units_consumed);
        assert!(result.compute_units_consumed <= 30_000, "split CU {} > 30,000", result.compute_units_consumed);
    }

    // ── burn_tokens ──
    {
        let treasury = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_account = Pubkey::new_unique();
        let token_account_owner = Pubkey::new_unique();

        let ts_data = make_split_token_state(
            &treasury, &Pubkey::new_unique(), &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let mut payload = Vec::new();
        payload.extend_from_slice(&1_000_000u64.to_le_bytes());
        payload.extend_from_slice(&build_string("zupy:v1:burn:123"));
        let data = build_ix_data(&DISC_BURN_TOKENS, &payload);

        let metas = vec![
            AccountMeta::new_readonly(treasury, true),
            AccountMeta::new_readonly(token_state_pda, false),
            AccountMeta::new(mint, false),
            AccountMeta::new(token_account, false),
            AccountMeta::new_readonly(token_account_owner, true),
            AccountMeta::new_readonly(token_2022_id(), false),
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = vec![
            (treasury, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 82])),
            (token_account, make_token_owned_account(make_token_account_data(&mint, &token_account_owner, 10_000_000))),
            (token_account_owner, make_system_account(1_000_000)),
            make_program_stub(&token_2022_id()),
        ];

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  burn_tokens             CU: {:>6}  (target ≤10,000)", result.compute_units_consumed);
        assert!(result.compute_units_consumed <= 10_000, "burn_tokens CU {} > 10,000", result.compute_units_consumed);
    }

    // ── burn_from_company_pda (compressed layout, 7 accounts) ──
    {
        let transfer_auth = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let company_id: u64 = 42;
        let (company_pda, _) = derive_company_pda(company_id);
        let fee_payer = Pubkey::new_unique();
        let ctoken_prog = Pubkey::new_from_array(zupy_token_program::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);

        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &transfer_auth, &mint, &Pubkey::new_unique(),
            &Pubkey::new_unique(), bump, true, false,
        );

        let mut payload = Vec::new();
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&1_000_000u64.to_le_bytes());
        payload.extend_from_slice(&build_string("zupy:v1:burn:42"));
        let data = build_ix_data(&DISC_BURN_FROM_COMPANY_PDA, &payload);

        let metas = vec![
            AccountMeta::new_readonly(transfer_auth, true),           // 0: signer
            AccountMeta::new_readonly(token_state_pda, false),        // 1
            AccountMeta::new(mint, false),                            // 2: writable
            AccountMeta::new_readonly(company_pda, false),            // 3
            AccountMeta::new(fee_payer, true),                        // 4: writable, signer
            AccountMeta::new_readonly(system_program_id(), false),    // 5
            AccountMeta::new_readonly(ctoken_prog, false),            // 6: Light cToken
        ];
        let instruction = Instruction::new_with_bytes(program_id(), &data, metas);
        let accounts = vec![
            (transfer_auth, make_system_account(1_000_000)),
            (token_state_pda, make_program_account(ts_data, 1_000_000)),
            (mint, make_token_owned_account(vec![0u8; 82])),
            (company_pda, make_program_account(vec![], 1_000_000)),
            (fee_payer, make_system_account(10_000_000)),
            make_program_stub(&system_program_id()),
            make_program_stub(&ctoken_prog),
        ];

        let result = mollusk.process_instruction(&instruction, &accounts);
        println!("  burn_from_company_pda   CU: {:>6}  (target ≤10,000)", result.compute_units_consumed);
        assert!(result.compute_units_consumed <= 10_000, "burn_company CU {} > 10,000", result.compute_units_consumed);
    }

    println!("═════════════════════════════════════════════════════════\n");
}
