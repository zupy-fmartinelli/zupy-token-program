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
///   [9+] Light system accounts (passed by client)
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
        user_id: u64, company_id: u64, z_total: u64,
        user_bump: u8, company_bump: u8, incentive_bump: u8,
        op_type: &str,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&z_total.to_le_bytes());
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
        let payload = build_payload(42, 99, 1_000_000, 0, 0, 0, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 0, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "invalid_type");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

    // ── Full compressed split flow (validation path) ──────────────────
    //
    // KNOWN LIMITATION: basic Mollusk does not load the Light cToken SBF binary,
    // so the actual compressed state changes (output leaf ownership, nullifier
    // insertion, mint supply decrement) cannot be asserted here. This test proves
    // all on-chain validation passes and the instruction correctly dispatches to
    // the first compressed CPI.
    //
    // Full verification (3-way state changes) requires a Light Protocol
    // integration environment with the cToken program loaded.
    // TODO: add full Light cToken integration test when available.

    #[test]
    fn test_full_split_flow_reaches_cpi_stage() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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

        // Must NOT fail at any validation error (zero, op_type, token_state, PDA, ctoken_program).
        // Will fail at first compressed CPI (Light cToken not loaded in basic Mollusk),
        // but that proves all on-chain validation passes.
        let is_validation_err = matches!(
            result.raw_result,
            Err(InstructionError::Custom(e)) if matches!(e, 6000..=6028)
        );
        assert!(
            !is_validation_err,
            "Must not fail at validation — expected CPI failure, got: {:?}",
            result.raw_result
        );
        println!(
            "split_transfer: full_split_flow_compressed CU={} (validation OK, fails at CPI as expected)",
            result.compute_units_consumed
        );
    }

    // ── CU benchmark with 3 compressed CPIs ──────────────────────────────

    #[test]
    fn test_cu_benchmark_compressed_validation_path() {
        let mollusk = setup_mollusk();
        let s = setup();
        let ts_data = make_split_token_state(
            &Pubkey::new_unique(), &s.transfer_auth, &s.mint, &Pubkey::new_unique(),
            &s.incentive_pool_pda, s.bump, true, false,
        );

        let payload = build_payload(s.user_id, s.company_id, 1_000_000, s.user_bump, s.company_bump, s.incentive_bump, "mixed_payment");
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
        // Measures CU through all on-chain validation + first CPI dispatch attempt.
        // Light cToken not loaded in basic Mollusk → fails at first cpi_compressed_transfer.
        // KNOWN LIMITATION: the 30,000 threshold covers the validation path only.
        // Actual CU for 3 compressed CPIs + ZK proof verification on mainnet-beta
        // must be measured in a full Light Protocol integration environment
        // before production deploy.
        println!(
            "  execute_split_transfer_compressed  CU: {:>6}  (validation-path only — 3×CPI CU unmeasured)",
            result.compute_units_consumed
        );
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

    // ── execute_split_transfer (compressed layout, 9 accounts) ──
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

        let mut payload = Vec::new();
        payload.extend_from_slice(&user_id.to_le_bytes());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(&1_000_000u64.to_le_bytes());
        payload.push(user_bump);
        payload.push(company_bump);
        payload.push(incentive_bump);
        payload.extend_from_slice(&build_string("mixed_payment"));
        let data = build_ix_data(&DISC_EXECUTE_SPLIT_TRANSFER, &payload);

        // New 9-account compressed layout
        let metas = vec![
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

        // Reaches first compressed CPI (Light cToken not loaded in basic Mollusk) —
        // measures CU through all on-chain validation + CPI dispatch.
        let result = mollusk.process_instruction(&instruction, &accounts);
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
