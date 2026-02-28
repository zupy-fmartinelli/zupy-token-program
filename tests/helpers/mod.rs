//! Shared Mollusk test helpers for zupy-pinocchio integration tests.
//!
//! Provides account factories, instruction builders, and assertion helpers
//! reused across all Mollusk test files.

use mollusk_svm::Mollusk;
use mollusk_svm::result::InstructionResult;
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_pubkey::Pubkey;

use zupy_pinocchio::constants::{
    ATA_PROGRAM_ID, PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_SEED,
    COMPANY_SEED, USER_SEED, INCENTIVE_POOL_SEED, DISTRIBUTION_POOL_SEED,
    RATE_LIMIT_SEED, ZUPY_CARD_SEED, ZUPY_CARD_MINT_SEED, COUPON_SEED,
    TREASURY_WALLET_PUBKEY, MINT_AUTHORITY_PUBKEY,
    BUBBLEGUM_PROGRAM_ID, SPL_ACCOUNT_COMPRESSION_ID, SPL_NOOP_ID,
    LIGHT_COMPRESSED_TOKEN_PROGRAM_ID,
    LIGHT_SYSTEM_PROGRAM_ID, REGISTERED_PROGRAM_PDA,
    ACCOUNT_COMPRESSION_AUTHORITY, ACCOUNT_COMPRESSION_PROGRAM_ID,
};
use zupy_pinocchio::state::token_state::{TOKEN_STATE_DISCRIMINATOR, TOKEN_STATE_SIZE};

// ── Light Protocol PDA helpers ───────────────────────────────────────────

/// Derive the Light SPL interface PDA (seeds: `["pool", mint]` on cToken program).
pub fn derive_spl_interface_pda(mint: &Pubkey) -> Pubkey {
    let ctoken_id = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    Pubkey::find_program_address(&[b"pool", mint.as_ref()], &ctoken_id).0
}

/// Derive the Light cToken CPI authority PDA (seeds: `["cpi_authority"]` on cToken program).
pub fn derive_ctoken_authority() -> Pubkey {
    let ctoken_id = Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
    Pubkey::find_program_address(&[b"cpi_authority"], &ctoken_id).0
}

// ── Program / constant helpers ───────────────────────────────────────────

pub fn program_id() -> Pubkey {
    Pubkey::new_from_array(PROGRAM_ID)
}

pub fn token_2022_id() -> Pubkey {
    Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID)
}

pub fn system_program_id() -> Pubkey {
    Pubkey::new_from_array(SYSTEM_PROGRAM_ID)
}

pub fn ata_program_id() -> Pubkey {
    Pubkey::new_from_array(ATA_PROGRAM_ID)
}

pub fn treasury_wallet() -> Pubkey {
    Pubkey::new_from_array(TREASURY_WALLET_PUBKEY)
}

pub fn mint_authority() -> Pubkey {
    Pubkey::new_from_array(MINT_AUTHORITY_PUBKEY)
}

pub fn bubblegum_program_id() -> Pubkey {
    Pubkey::new_from_array(BUBBLEGUM_PROGRAM_ID)
}

pub fn ctoken_program_id() -> Pubkey {
    Pubkey::new_from_array(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID)
}

pub fn compression_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_ACCOUNT_COMPRESSION_ID)
}

pub fn noop_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_NOOP_ID)
}

pub fn light_system_program_id() -> Pubkey {
    Pubkey::new_from_array(LIGHT_SYSTEM_PROGRAM_ID)
}

pub fn registered_program_pda_id() -> Pubkey {
    Pubkey::new_from_array(REGISTERED_PROGRAM_PDA)
}

pub fn account_compression_authority_id() -> Pubkey {
    Pubkey::new_from_array(ACCOUNT_COMPRESSION_AUTHORITY)
}

pub fn account_compression_program_id() -> Pubkey {
    Pubkey::new_from_array(ACCOUNT_COMPRESSION_PROGRAM_ID)
}

// ── Mollusk setup ────────────────────────────────────────────────────────

/// Create Mollusk with just our program (for validation-path benchmarks).
pub fn setup_mollusk() -> Mollusk {
    Mollusk::new(&program_id(), "zupy_pinocchio")
}

/// Create Mollusk with Token-2022, ATA, and System programs loaded.
/// This enables full happy-path CPI execution.
pub fn setup_mollusk_with_programs() -> Mollusk {
    let mut mollusk = setup_mollusk();
    mollusk_svm_programs_token::token2022::add_program(&mut mollusk);
    mollusk_svm_programs_token::associated_token::add_program(&mut mollusk);
    mollusk
}

// ── PDA derivation helpers ───────────────────────────────────────────────

pub fn derive_token_state_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TOKEN_STATE_SEED], &program_id())
}

pub fn derive_company_pda(company_id: u64) -> (Pubkey, u8) {
    let id_bytes = company_id.to_le_bytes();
    Pubkey::find_program_address(&[COMPANY_SEED, &id_bytes], &program_id())
}

pub fn derive_user_pda(user_id: u64) -> (Pubkey, u8) {
    let id_bytes = user_id.to_le_bytes();
    Pubkey::find_program_address(&[USER_SEED, &id_bytes], &program_id())
}

pub fn derive_incentive_pool_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[INCENTIVE_POOL_SEED], &program_id())
}

pub fn derive_distribution_pool_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[DISTRIBUTION_POOL_SEED], &program_id())
}

pub fn derive_rate_limit_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RATE_LIMIT_SEED, authority.as_ref()], &program_id())
}

pub fn derive_zupy_card_pda(user_ksuid: &[u8; 27]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ZUPY_CARD_SEED, user_ksuid], &program_id())
}

pub fn derive_zupy_card_mint_pda(user_ksuid: &[u8; 27]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ZUPY_CARD_MINT_SEED, user_ksuid], &program_id())
}

pub fn derive_coupon_pda(coupon_ksuid: &[u8; 27]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[COUPON_SEED, coupon_ksuid], &program_id())
}

// We also need user_pda derived with b"user_pda" seed (different from USER_SEED)
pub fn derive_user_pda_by_ksuid(user_ksuid: &[u8; 27]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"user_pda", user_ksuid], &program_id())
}

// ── Account factory helpers ──────────────────────────────────────────────

/// Create a TokenState account data buffer (TOKEN_STATE_SIZE bytes).
/// This is the full-featured version with all fields configurable.
pub fn make_token_state_data(
    treasury: &Pubkey,
    mint_authority: &Pubkey,
    transfer_auth: &Pubkey,
    pool_ata: &Pubkey,
    distribution_pool: &Pubkey,
    incentive_pool: &Pubkey,
    treasury_ata: &Pubkey,
    mint: &Pubkey,
    bump: u8,
    initialized: bool,
    paused: bool,
) -> Vec<u8> {
    let mut data = vec![0u8; TOKEN_STATE_SIZE];
    data[0..8].copy_from_slice(&TOKEN_STATE_DISCRIMINATOR);
    data[8..40].copy_from_slice(treasury.as_ref());           // treasury
    data[40..72].copy_from_slice(mint_authority.as_ref());     // mint_authority
    data[72..104].copy_from_slice(transfer_auth.as_ref());     // transfer_authority
    data[104..136].copy_from_slice(pool_ata.as_ref());         // pool_ata
    data[136..168].copy_from_slice(distribution_pool.as_ref()); // distribution_pool
    data[168..200].copy_from_slice(incentive_pool.as_ref());   // incentive_pool
    data[200..232].copy_from_slice(treasury_ata.as_ref());     // treasury_ata
    data[232..264].copy_from_slice(mint.as_ref());             // mint
    data[264] = initialized as u8;
    data[265] = bump;
    // per_tx_auto_limit (266..274), daily_auto_limit (274..282)
    data[266..274].copy_from_slice(&1_000_000u64.to_le_bytes()); // 1M per tx
    data[274..282].copy_from_slice(&10_000_000u64.to_le_bytes()); // 10M daily
    // daily_minted (282..290) = 0
    // last_reset_timestamp (290..298) = 0
    data[298] = paused as u8;
    data
}

/// Simplified token_state builder for tests that only need transfer fields.
pub fn make_transfer_token_state(
    transfer_auth: &Pubkey,
    mint: &Pubkey,
    pool_ata: &Pubkey,
    bump: u8,
    initialized: bool,
    paused: bool,
) -> Vec<u8> {
    let dummy = Pubkey::new_unique();
    make_token_state_data(
        &dummy, &dummy, transfer_auth, pool_ata, &dummy, &dummy, &dummy, mint,
        bump, initialized, paused,
    )
}

/// Token_state builder for split-transfer tests (needs treasury + incentive_pool).
pub fn make_split_token_state(
    treasury: &Pubkey,
    transfer_auth: &Pubkey,
    mint: &Pubkey,
    pool_ata: &Pubkey,
    incentive_pool: &Pubkey,
    bump: u8,
    initialized: bool,
    paused: bool,
) -> Vec<u8> {
    let dummy = Pubkey::new_unique();
    make_token_state_data(
        treasury, &dummy, transfer_auth, pool_ata, &dummy, incentive_pool, &dummy, mint,
        bump, initialized, paused,
    )
}

/// Create a Token-2022 token account data buffer (165 bytes).
/// Layout: mint(32) + owner(32) + amount(8 LE) + ... + state=Initialized(1) @ offset 108
pub fn make_token_account_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1; // AccountState::Initialized
    data
}

/// Create a Token-2022 mint data buffer (82 bytes).
/// Minimal valid mint: supply, decimals, initialized, authority.
pub fn make_mint_data(authority: &Pubkey, supply: u64, decimals: u8) -> Vec<u8> {
    let mut data = vec![0u8; 82];
    // COption<Pubkey> mint_authority: tag(4) + pubkey(32)
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // Some
    data[4..36].copy_from_slice(authority.as_ref());
    // supply: u64
    data[36..44].copy_from_slice(&supply.to_le_bytes());
    // decimals: u8
    data[44] = decimals;
    // is_initialized: bool
    data[45] = 1;
    // freeze_authority: COption<Pubkey> = None
    data[46..50].copy_from_slice(&0u32.to_le_bytes());
    data
}

/// Create a system account (for signers, payers, etc.).
pub fn make_system_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: Pubkey::default(), // system program owns it
        executable: false,
        rent_epoch: 0,
    }
}

/// Create an account owned by our program (for PDAs).
pub fn make_program_account(data: Vec<u8>, lamports: u64) -> Account {
    Account {
        lamports,
        data,
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Create a Token-2022-owned account (for mints and token accounts).
/// Uses rent-exempt formula: (128 + data_len) * 3480 * 2  (Rent::default())
pub fn make_token_owned_account(data: Vec<u8>) -> Account {
    let lamports = ((128 + data.len() as u64) * 3480 * 2).max(1);
    Account {
        lamports,
        data,
        owner: token_2022_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Create an executable program account stub.
pub fn make_program_stub(id: &Pubkey) -> (Pubkey, Account) {
    (*id, Account {
        lamports: 1,
        data: vec![],
        owner: Pubkey::default(),
        executable: true,
        rent_epoch: 0,
    })
}

// ── Instruction data builders ────────────────────────────────────────────

/// Build instruction data: 8-byte discriminator + payload.
pub fn build_ix_data(disc: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(disc);
    data.extend_from_slice(payload);
    data
}

/// Build a length-prefixed string (4-byte LE length + UTF-8).
pub fn build_string(s: &str) -> Vec<u8> {
    let len = s.len() as u32;
    let mut buf = Vec::with_capacity(4 + s.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf
}

// ── Assertion helpers ────────────────────────────────────────────────────

/// Assert Mollusk result is a specific custom error code.
pub fn assert_ix_custom_err(result: &InstructionResult, expected_code: u32) {
    assert_eq!(
        result.raw_result,
        Err(InstructionError::Custom(expected_code)),
        "Expected Custom({}), got {:?}",
        expected_code,
        result.raw_result,
    );
}

/// Assert Mollusk result is NotEnoughAccountKeys.
#[allow(deprecated)] // solana_instruction renamed to MissingAccount, but runtime still returns this
pub fn assert_ix_not_enough_keys(result: &InstructionResult) {
    assert_eq!(
        result.raw_result,
        Err(InstructionError::NotEnoughAccountKeys),
        "Expected NotEnoughAccountKeys, got {:?}",
        result.raw_result,
    );
}

// ── CU benchmark result tracking ─────────────────────────────────────────

/// CU measurement result for a single instruction benchmark.
#[derive(Clone, Debug)]
pub struct CuResult {
    pub name: &'static str,
    pub classification: &'static str,
    pub anchor_est: u64,
    pub pinocchio_cu: u64,
    pub max_allowed: u64,
    pub passed: bool,
    pub note: String,
}

impl CuResult {
    pub fn savings_pct(&self) -> f64 {
        if self.anchor_est == 0 { return 0.0; }
        (1.0 - (self.pinocchio_cu as f64 / self.anchor_est as f64)) * 100.0
    }

    pub fn status_str(&self) -> &'static str {
        if self.passed { "PASS" } else { "FAIL" }
    }

    pub fn warn_close(&self) -> bool {
        self.pinocchio_cu as f64 > self.max_allowed as f64 * 0.8
    }
}
