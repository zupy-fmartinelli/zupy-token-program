//! Light Protocol CPI helpers for compressed token operations.
//!
//! This module exposes CPI helper functions for the Light Protocol operation paths:
//!
//! ## Path A — SPL → Compressed (`compress_spl_token_account`)
//!
//! - [`cpi_compress_from_spl`]: Pool ATA → compressed leaf.
//!   Uses `compress_spl_token_account` instruction (Anchor 8-byte disc `[112, 230, ...]`,
//!   cu=2064). 13 fixed accounts + Merkle tree output queue as remaining accounts.
//! - [`cpi_decompress_to_spl`]: Compressed leaf → SPL ATA.
//!   Uses Transfer2 (disc=101). Dispatches, accounts accepted, reaches business logic.
//!
//! ## Path B — Compressed → Compressed (ZK proof required)
//!
//! - [`cpi_compressed_transfer`]: Compressed → compressed transfer.
//!   Requires `ValidityProof` for input account existence.
//!
//! ## Path C — Compressed Burn
//!
//! - [`cpi_compressed_burn`]: Burn from a compressed account.
//!   Implemented: disc=8, accounts=[authority, mint, fee_payer].
//!
//! ## Implementation Note: Pinocchio Version Compatibility
//!
//! `light-token-pinocchio 0.22.0` depends on `pinocchio = "0.9"` while our program
//! uses `pinocchio = "0.10"`. These have different types (`AccountInfo` vs `AccountView`),
//! so we cannot call SDK CPI helpers directly. Instruction data is built manually
//! (Borsh layout verified via on-chain simulation) and invoked via
//! `pinocchio::cpi::invoke_signed_with_slice` with `InstructionView`.
//!
//! ## SDK Compatibility Note
//!
//! `light-token-pinocchio 0.22.0` uses `TRANSFER2_DISCRIMINATOR: u8 = 101`.
//! Devnet simulation confirmed disc=101 dispatches to Transfer2 on the deployed cToken program
//! (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`). This is the current live interface —
//! NOT a legacy value. `compress_spl_token_account` remains Anchor 8-byte (separate codepath).
//!
//! ## Mainnet V1/V2 Incompatibility
//!
//! **Mainnet** cToken runs V1 (Anchor-based, 642KB). **Devnet** runs V2
//! (Pinocchio-based, 1.2MB). No public Light Protocol upgrade timeline exists.
//!
//! | Operation | V1 Disc | V2 Disc | Mainnet Status |
//! |-----------|---------|---------|----------------|
//! | `compress_spl_token_account` | 8-byte Anchor | 8-byte Anchor | **WORKS** |
//! | Transfer2 (decompress/transfer) | N/A | disc=101 | **BLOCKED** |
//! | Transfer (V1 unified) | `[163,52,200,231,140,3,69,186]` | N/A | **WORKS** |
//! | Burn | N/A | disc=8 | **BLOCKED** |
//!
//! For mainnet decompress operations, use [`TRANSFER_V1_DISC`] with the V1 CPI passthrough
//! instruction (`return_user_to_pool_v1`). The backend builds the full V1 Borsh
//! `CompressedTokenInstructionDataTransfer` and our on-chain program validates + forwards.

use pinocchio::AccountView;
use pinocchio::Address;
use pinocchio::cpi::Signer;
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};

use crate::constants::{LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, TOKEN_DECIMALS};

// ── Discriminators ────────────────────────────────────────────────────────────
/// Anchor 8-byte discriminator for `compress_spl_token_account` (Path A compress).
///
/// = SHA256("global:compress_spl_token_account")[0..8]
/// Verified on mainnet cToken program (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`):
/// dispatched with cu=2064, log "Instruction: CompressSplTokenAccount".
const COMPRESS_SPL_TOKEN_ACCOUNT_DISC: [u8; 8] = [112, 230, 105, 101, 145, 202, 157, 97];

/// Single-byte discriminator for the Transfer2 interface (cToken program).
///
/// `light-token-pinocchio 0.22.0` `transfer_to_spl.rs` and `transfer_from_spl.rs` both use
/// `TRANSFER2_DISCRIMINATOR: u8 = 101`. This is NOT a legacy value — it is the current
/// on-chain discriminator for compressed↔SPL operations via the Transfer2
/// (`CompressedTokenInstructionDataTransfer2`) path.
///
/// Note: Transfer2 dispatches via a 1-byte discriminator, not an Anchor instruction name.
const TRANSFER2_DISC: u8 = 101;

/// V1 TRANSFER discriminator for the Light cToken program (Anchor 8-byte).
///
/// = SHA256("global:transfer")[0..8]
/// Used by **mainnet** V1 cToken for ALL transfer operations (compress, decompress,
/// compressed-to-compressed). Decompress mode uses `is_compress = false` with
/// `compress_or_decompress_amount = Some(amount)`.
///
/// The backend builds the full V1 `CompressedTokenInstructionDataTransfer` in Borsh
/// format and passes it to the `return_user_to_pool_v1` instruction for CPI passthrough.
///
/// **Context:** Mainnet cToken (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`) runs V1
/// (Anchor-based, 642KB). Transfer2 (disc=101) only works on devnet V2.
pub(crate) const TRANSFER_V1_DISC: [u8; 8] = [163, 52, 200, 231, 140, 3, 69, 186];

/// Validates that raw CPI data starts with the V1 TRANSFER discriminator.
///
/// Security check for the CPI passthrough pattern: ensures the backend can only
/// submit V1 TRANSFER instructions to the cToken program (prevents misuse with
/// other cToken instruction types like initialize, freeze, etc.).
///
/// Returns `InvalidInstructionData` if data is too short or prefix doesn't match.
pub(crate) fn validate_v1_transfer_disc(cpi_data: &[u8]) -> Result<(), ProgramError> {
    if cpi_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if cpi_data[0..8] != TRANSFER_V1_DISC {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

// ── Pure Data Builders (unit-testable) ────────────────────────────────────────

/// Builds the 42-byte Borsh-encoded `compress_spl_token_account` instruction data
/// for a **full compress** (`remaining_amount = None` — compress ALL tokens).
///
/// Use for migration scenarios where the entire SPL balance is to be compressed.
///
/// Layout (Anchor Borsh):
///
/// ```text
/// [0..8]  disc = COMPRESS_SPL_TOKEN_ACCOUNT_DISC (Anchor 8-byte SHA256)
/// [8..40] owner: Pubkey (32 bytes — compressed-token recipient)
/// [40]    remaining_amount: Option<u64> = None (0x00)
/// [41]    cpi_context: Option<CompressedCpiContext> = None (0x00)
/// ```
///
/// The cToken program transfers ALL tokens from the source ATA into a compressed
/// Merkle-tree leaf owned by `owner`. No SPL remains in the source account.
#[inline]
pub(crate) fn build_compress_all_data(owner: &[u8; 32]) -> [u8; 42] {
    let mut d = [0u8; 42];
    d[0..8].copy_from_slice(&COMPRESS_SPL_TOKEN_ACCOUNT_DISC);
    d[8..40].copy_from_slice(owner.as_ref());
    // d[40] = remaining_amount: None (0x00)
    // d[41] = cpi_context: None (0x00)
    d
}

/// Builds the 50-byte Borsh-encoded `compress_spl_token_account` instruction data
/// for a **partial compress** (`remaining_amount = Some(remaining)`).
///
/// Use for `transfer_from_pool`: compress `amount` tokens and keep `pool_balance - amount`
/// as SPL in the source ATA.
///
/// Layout (Anchor Borsh):
///
/// ```text
/// [0..8]   disc = COMPRESS_SPL_TOKEN_ACCOUNT_DISC (Anchor 8-byte SHA256)
/// [8..40]  owner: Pubkey (32 bytes — compressed-token recipient)
/// [40]     remaining_amount: Option<u64> = Some (0x01)
/// [41..49] remaining_amount value (u64 LE — SPL tokens to keep in source ATA)
/// [49]     cpi_context: Option<CompressedCpiContext> = None (0x00)
/// ```
///
/// `remaining` is the number of SPL tokens to KEEP in the source ATA after compression.
/// To compress `amount` from a pool with `pool_balance`: pass `remaining = pool_balance - amount`.
#[inline]
pub(crate) fn build_compress_with_remaining_data(owner: &[u8; 32], remaining: u64) -> [u8; 50] {
    let mut d = [0u8; 50];
    d[0..8].copy_from_slice(&COMPRESS_SPL_TOKEN_ACCOUNT_DISC);
    d[8..40].copy_from_slice(owner.as_ref());
    d[40] = 1; // Some
    d[41..49].copy_from_slice(&remaining.to_le_bytes());
    // d[49] = cpi_context: None (0x00)
    d
}

/// Builds the 59-byte Borsh-encoded `CompressedTokenInstructionDataTransfer2` for a
/// **Path A decompress** operation (compressed leaf → Pool ATA).
///
/// **Layout verification:** Byte offsets derived from `light-token-interface 0.5.0` source
/// (`Compression::decompress_spl` and `Compression::compress` factory methods).
/// Same 59-byte structure as the old Transfer2 format (modes swapped) with
/// account indices adjusted for reversed roles:
///
/// Packed account layout (6 packed, no separate SPL source ATA):
///   - packed[0] = mint
///   - packed[1] = destination_spl (pool_ata — receives unlocked SPL)
///   - packed[2] = authority (source PDA — compressed account signer)
///   - packed[3] = spl_interface_pda (holds locked SPL)
///
/// ```text
/// [0]     disc = 101
/// [1..5]  header flags = 0
/// [6..7]  max_top_up = u16::MAX (LE) — no top-up limit
/// [8]     cpi_context = None (0)
/// [9]     compressions = Some (1)
/// [10..13] vec len = 2 (u32 LE)
/// [14..29] Compression 0: decompress_spl(amount, mint=0, recipient=1, pool=3, idx=0, bump, dec=6)
/// [30..45] Compression 1: compress(amount, mint=0, source=2, auth=2)
/// [46]    proof = None (0)
/// [47..50] in_token_data len = 0 (u32 LE)
/// [51..54] out_token_data len = 0 (u32 LE)
/// [55..58] in/out lamports/tlv = None (all zeros)
/// ```
#[inline]
pub(crate) fn build_decompress_to_spl_data(amount: u64, spl_bump: u8) -> [u8; 59] {
    let mut d = [0u8; 59];
    let ab = amount.to_le_bytes();

    // ── Header ───────────────────────────────────────────────────────────────
    d[0] = TRANSFER2_DISC;
    // d[1] = with_transaction_hash: false (0)
    // d[2] = with_lamports_change_account_merkle_tree_index: false (0)
    // d[3] = lamports_change_account_merkle_tree_index: 0
    // d[4] = lamports_change_account_owner_index: 0
    // d[5] = output_queue: 0
    d[6] = 0xFF; // max_top_up low byte
    d[7] = 0xFF; // max_top_up high byte (= u16::MAX)
    // d[8] = cpi_context: None (0)
    // ── compressions: Some(vec![...]) ────────────────────────────────────────
    d[9] = 1; // Some
    d[10] = 2; // vec len low byte (= 2, u32 LE)
    // d[11..13] = 0 (high bytes of u32 len)
    // ── Compression 0: decompress_spl (releases SPL from spl_interface_pda to pool_ata) ──
    d[14] = 1; // mode: CompressionMode::Decompress = 1
    d[15..23].copy_from_slice(&ab); // amount (u64 LE)
    // d[23] = mint index = 0 (packed[0])
    d[24] = 1; // source_or_recipient = 1 (packed[1] = pool_ata, SPL destination)
    // d[25] = authority = 0 (UNUSED for decompress_spl per light-token-interface source)
    d[26] = 3; // pool_account_index = 3 (packed[3] = spl_interface_pda)
    // d[27] = pool_index = 0
    d[28] = spl_bump; // spl_interface_pda bump
    d[29] = TOKEN_DECIMALS; // decimals = 6
    // ── Compression 1: compress (spends the authority's compressed account) ─────
    d[30] = 0; // mode: CompressionMode::Compress = 0
    d[31..39].copy_from_slice(&ab); // amount (u64 LE)
    // d[39] = mint index = 0 (packed[0])
    d[40] = 2; // source_or_recipient = 2 (packed[2] = source PDA, compressed source)
    d[41] = 2; // authority = 2 (packed[2] = source PDA, signer)
    // d[42] = pool_account_index = 0 (unused — no pool for compress without SPL)
    // d[43] = pool_index = 0 (unused)
    // d[44] = bump = 0 (unused)
    // d[45] = decimals = 0 (unused)
    // ── Trailing None/empty fields ────────────────────────────────────────────
    // d[46] = proof: None (0)
    // d[47..50] = in_token_data: vec![] len = 0 (all zeros)
    // d[51..54] = out_token_data: vec![] len = 0 (all zeros)
    // d[55] = in_lamports: None (0)
    // d[56] = out_lamports: None (0)
    // d[57] = in_tlv: None (0)
    // d[58] = out_tlv: None (0)

    d
}

// ── Path A: cpi_compress_from_spl ─────────────────────────────────────────────

/// CPI: Compress tokens from a source SPL ATA into a compressed Merkle-tree leaf.
///
/// **Path A** — no ZK proof required. Calls the Light cToken program with the
/// `compress_spl_token_account` instruction (Anchor 8-byte disc, cu=2064). The
/// `authority` must sign (token_state PDA that owns the source ATA).
///
/// The cToken program transfers SPL tokens from `source_ata` into `token_pool_pda`
/// (Light SPL interface pool), minting a compressed token leaf owned by `owner`
/// in the specified Merkle tree.
///
/// `remaining_amount`: SPL tokens to keep in `source_ata` after compression.
/// - `None` → compress the entire ATA balance
/// - `Some(x)` → compress `balance - x` tokens, keep `x` as SPL
///
/// ## Account order passed to cToken program
/// ```text
/// [0]  fee_payer                    (writable, signer)
/// [1]  authority                    (readonly, signer)  — token_state PDA
/// [2]  cpi_authority_pda            (readonly)          — LIGHT_TOKEN_CPI_AUTHORITY
/// [3]  light_system_program         (readonly)          — LIGHT_SYSTEM_PROGRAM_ID
/// [4]  registered_program_pda       (readonly)          — REGISTERED_PROGRAM_PDA
/// [5]  noop_program                 (readonly)          — SPL_NOOP_ID
/// [6]  account_compression_authority (readonly)         — ACCOUNT_COMPRESSION_AUTHORITY
/// [7]  account_compression_program  (readonly)          — ACCOUNT_COMPRESSION_PROGRAM_ID
/// [8]  self_program (cToken)        (readonly)          — LIGHT_COMPRESSED_TOKEN_PROGRAM_ID
/// [9]  token_pool_pda               (writable)          — spl_interface_pda
/// [10] source_ata                   (writable)          — source SPL token account
/// [11] token_program                (readonly)          — Token-2022
/// [12] system_program               (readonly)
/// [13+] remaining_accounts          — Merkle tree output queue
/// ```
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn cpi_compress_from_spl<'a>(
    compressed_token_program: &'a AccountView,         // [8]  self (cToken program)
    cpi_authority_pda: &'a AccountView,                // [2]  LIGHT_TOKEN_CPI_AUTHORITY
    light_system_program: &'a AccountView,             // [3]  LIGHT_SYSTEM_PROGRAM_ID
    registered_program_pda: &'a AccountView,           // [4]  REGISTERED_PROGRAM_PDA
    noop_program: &'a AccountView,                     // [5]  SPL_NOOP_ID
    account_compression_authority: &'a AccountView,    // [6]  ACCOUNT_COMPRESSION_AUTHORITY
    account_compression_program: &'a AccountView,      // [7]  ACCOUNT_COMPRESSION_PROGRAM_ID
    fee_payer: &'a AccountView,                        // [0]
    authority: &'a AccountView,                        // [1]  token_state PDA (signer)
    token_pool_pda: &'a AccountView,                   // [9]  spl_interface_pda (writable)
    source_ata: &'a AccountView,                       // [10] source SPL ATA (writable)
    token_program: &'a AccountView,                    // [11] Token-2022
    system_program: &'a AccountView,                   // [12]
    owner: &[u8; 32],                                  // instruction param: recipient pubkey
    remaining_amount: Option<u64>,                     // instruction param: SPL to keep
    remaining_accounts: &'a [AccountView],             // Merkle tree output queue + others
    signers: &[Signer],
) -> Result<(), ProgramError> {
    // Build instruction data (42 bytes for None, 50 bytes for Some)
    let data: Vec<u8> = match remaining_amount {
        None    => build_compress_all_data(owner).to_vec(),
        Some(r) => build_compress_with_remaining_data(owner, r).to_vec(),
    };

    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();

    // Build 13 fixed account metas + remaining
    let mut account_metas = Vec::with_capacity(13 + remaining_accounts.len());
    account_metas.push(InstructionAccount::writable_signer(fee_payer.address()));               // [0]
    account_metas.push(InstructionAccount::readonly_signer(authority.address()));               // [1]
    account_metas.push(InstructionAccount::readonly(cpi_authority_pda.address()));             // [2]
    account_metas.push(InstructionAccount::readonly(light_system_program.address()));          // [3]
    account_metas.push(InstructionAccount::readonly(registered_program_pda.address()));        // [4]
    account_metas.push(InstructionAccount::readonly(noop_program.address()));                  // [5]
    account_metas.push(InstructionAccount::readonly(account_compression_authority.address())); // [6]
    account_metas.push(InstructionAccount::readonly(account_compression_program.address()));   // [7]
    account_metas.push(InstructionAccount::readonly(compressed_token_program.address()));      // [8] self
    account_metas.push(InstructionAccount::writable(token_pool_pda.address()));                // [9]
    account_metas.push(InstructionAccount::writable(source_ata.address()));                    // [10]
    account_metas.push(InstructionAccount::readonly(token_program.address()));                 // [11]
    account_metas.push(InstructionAccount::readonly(system_program.address()));                // [12]
    for acct in remaining_accounts {
        let meta = match (acct.is_writable(), acct.is_signer()) {
            (true, true)  => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _             => InstructionAccount::readonly(acct.address()),
        };
        account_metas.push(meta);
    }

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: &data,
    };

    // Build account view slice: 13 fixed accounts + remaining
    let mut account_views: Vec<&AccountView> = Vec::with_capacity(13 + remaining_accounts.len());
    account_views.push(fee_payer);                      // [0]
    account_views.push(authority);                      // [1]
    account_views.push(cpi_authority_pda);              // [2]
    account_views.push(light_system_program);           // [3]
    account_views.push(registered_program_pda);         // [4]
    account_views.push(noop_program);                   // [5]
    account_views.push(account_compression_authority);  // [6]
    account_views.push(account_compression_program);    // [7]
    account_views.push(compressed_token_program);       // [8] self
    account_views.push(token_pool_pda);                 // [9]
    account_views.push(source_ata);                     // [10]
    account_views.push(token_program);                  // [11]
    account_views.push(system_program);                 // [12]
    account_views.extend(remaining_accounts.iter());

    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, signers)?;
    Ok(())
}

// ── Path A (reverse): cpi_decompress_to_spl ───────────────────────────────────

/// CPI: Decompress tokens from a compressed leaf into a destination SPL ATA (pool_ata).
///
/// **Path A (reverse)** — no ZK proof required. Reverse of [`cpi_compress_from_spl`].
/// Used by `return_to_pool` and `return_user_to_pool`.
///
/// Simulation with disc=101, 59-byte instruction data, and 8 fixed accounts produced
/// `"Program log: Transfer2"` + `"Cannot decompress if no balance exists"` (error 6005).
/// This confirms the instruction dispatches, accounts are accepted, and the program reaches
/// business logic. Error 6005 = expected when `spl_interface_pda` holds no SPL balance.
///
/// Two `Compression` entries processed atomically:
/// 1. `decompress_spl`: releases `amount` SPL tokens from `spl_interface_pda` to `destination_spl`.
/// 2. `compress`: spends `amount` from `authority`'s compressed leaf (verified via Light system
///    accounts at the end of the accounts slice).
///
/// ## Account order passed to cToken program
/// ```text
/// [0] compressed_token_authority (readonly)
/// [1] payer                       (writable, signer)
/// packed:
/// [2] mint                        (readonly)          → packed[0]
/// [3] destination_spl (pool_ata)  (writable)          → packed[1]
/// [4] authority (source PDA)      (readonly, signer)  → packed[2]
/// [5] spl_interface_pda           (writable)          → packed[3]
/// [6] spl_token_program           (readonly)          → packed[4]
/// [7] system_program              (readonly)          → packed[5]
/// [8+] Light system accounts (Merkle tree, nullifier queue, noop)
/// ```
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn cpi_decompress_to_spl<'a>(
    _compressed_token_program: &'a AccountView,
    compressed_token_authority: &'a AccountView,
    payer: &'a AccountView,
    mint: &'a AccountView,
    destination_spl: &'a AccountView,
    authority: &'a AccountView,
    spl_interface_pda: &'a AccountView,
    spl_token_program: &'a AccountView,
    system_program: &'a AccountView,
    amount: u64,
    spl_interface_pda_bump: u8,
    remaining_accounts: &'a [AccountView],
    signers: &[Signer],
) -> Result<(), ProgramError> {
    let data = build_decompress_to_spl_data(amount, spl_interface_pda_bump);

    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();

    // Build fixed account metas; append remaining Light system accounts (Merkle tree, etc.)
    let mut account_metas = Vec::with_capacity(8 + remaining_accounts.len());
    account_metas.push(InstructionAccount::readonly(compressed_token_authority.address()));  // [0]
    account_metas.push(InstructionAccount::writable_signer(payer.address()));                // [1]
    account_metas.push(InstructionAccount::readonly(mint.address()));                         // packed[0]
    account_metas.push(InstructionAccount::writable(destination_spl.address()));             // packed[1]
    account_metas.push(InstructionAccount::readonly_signer(authority.address()));            // packed[2]
    account_metas.push(InstructionAccount::writable(spl_interface_pda.address()));           // packed[3]
    account_metas.push(InstructionAccount::readonly(spl_token_program.address()));           // packed[4]
    account_metas.push(InstructionAccount::readonly(system_program.address()));              // packed[5]
    for acct in remaining_accounts {
        let meta = match (acct.is_writable(), acct.is_signer()) {
            (true, true)  => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _             => InstructionAccount::readonly(acct.address()),
        };
        account_metas.push(meta);
    }

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: &data,
    };

    // Build account view slice matching instruction.accounts 1:1 (no program account).
    // Pinocchio 0.10 resolves the CPI target program from InstructionView.program_id,
    // NOT from the account_views slice. Including the program here would shift
    // remaining_accounts by one position, causing pubkey mismatches in
    // inner_invoke_signed_with_slice (ProgramError::InvalidArgument).
    let mut account_views: Vec<&AccountView> = Vec::with_capacity(8 + remaining_accounts.len());
    account_views.push(compressed_token_authority);
    account_views.push(payer);
    account_views.push(mint);
    account_views.push(destination_spl);
    account_views.push(authority);
    account_views.push(spl_interface_pda);
    account_views.push(spl_token_program);
    account_views.push(system_program);
    account_views.extend(remaining_accounts.iter());

    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, signers)?;
    Ok(())
}

// ── Path B: cpi_compressed_transfer ───────────────────────────────────────────

/// Builds the 9-byte instruction data for the Light cToken `Transfer` instruction (disc=3).
///
/// Layout (from `light-token-pinocchio 0.22.0` `TransferCpi::invoke_signed`):
/// ```text
/// [0]    discriminator = 3 (Transfer)
/// [1..9] amount (u64 LE)
/// ```
///
/// The cToken program validates that `authority` owns the `source` compressed token
/// balance and transfers `amount` to `destination`. No ValidityProof is passed in
/// instruction data — the source authority's PDA signature is sufficient.
#[inline]
pub(crate) fn build_compressed_transfer_data(amount: u64) -> [u8; 9] {
    let mut d = [0u8; 9];
    d[0] = 3u8; // Transfer discriminator
    d[1..9].copy_from_slice(&amount.to_le_bytes());
    d
}

/// CPI: Transfer tokens between two compressed accounts (Path B).
///
/// Calls the Light cToken program (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`)
/// with `Transfer` instruction (discriminator = 3). The `authority` must sign (typically
/// the source PDA, signing via `signers` seeds).
///
/// ## Account order passed to the cToken program
/// ```text
/// [0] source      (writable)            — compressed token source owner
/// [1] destination (writable)            — compressed token destination owner
/// [2] authority   (readonly, signer)    — source owner signer (PDA)
/// [3] system_program (readonly)
/// [4] fee_payer   (writable, signer)
/// ```
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn cpi_compressed_transfer<'a>(
    compressed_token_program: &'a AccountView,
    fee_payer: &'a AccountView,
    source: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView,
    system_program: &'a AccountView,
    amount: u64,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    let data = build_compressed_transfer_data(amount);
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();

    let accounts = [
        InstructionAccount::writable(source.address()),           // [0] source
        InstructionAccount::writable(destination.address()),      // [1] destination
        InstructionAccount::readonly_signer(authority.address()), // [2] authority (PDA signer)
        InstructionAccount::readonly(system_program.address()),   // [3] system_program
        InstructionAccount::writable_signer(fee_payer.address()), // [4] fee_payer
    ];

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &accounts,
        data: &data,
    };

    pinocchio::cpi::invoke_signed(
        &instruction,
        &[
            source,
            destination,
            authority,
            system_program,
            fee_payer,
            compressed_token_program, // program account LAST
        ],
        signers,
    )?;
    Ok(())
}

// ── Path C: cpi_compressed_burn ───────────────────────────────────────────────

/// Discriminator for the Light cToken `Burn` instruction.
///
/// Value `8` is verified from `light-token-pinocchio 0.22.0` source
/// (`src/instruction/burn.rs`): `data[0] = 8u8; // Burn discriminator`.
const BURN_DISC: u8 = 8;

/// Builds the 9-byte Borsh-encoded instruction data for the Light cToken `Burn` instruction.
///
/// Layout (mirrors `build_compressed_transfer_data` for Transfer, disc=3):
/// ```text
/// [0]    discriminator = 8 (Burn)
/// [1..9] amount (u64 LE)
/// ```
///
/// The cToken program validates that `authority` owns the compressed token balance,
/// nullifies the input leaf (destroying the compressed tokens), and decrements
/// the on-chain mint supply.
#[inline]
pub(crate) fn build_compressed_burn_data(amount: u64) -> [u8; 9] {
    let mut d = [0u8; 9];
    d[0] = BURN_DISC;
    d[1..9].copy_from_slice(&amount.to_le_bytes());
    d
}

/// CPI: Burn tokens from a compressed account (Path C).
///
/// Calls the Light cToken program (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`)
/// with `Burn` instruction (discriminator = 8). The `authority` must sign (typically
/// the source PDA, signing via `signers` seeds). The `mint` supply is decremented
/// on-chain.
///
/// Account layout matches `light-token-pinocchio 0.22.0` `BurnCpi` (with fee_payer):
/// `authority` is passed twice — as `source` (writable) and as `authority`
/// (readonly_signer). The Solana runtime deduplicates same-pubkey accounts,
/// resulting in writable_signer for the combined entry.
///
/// ## Account order passed to the cToken program
/// ```text
/// [0] authority   (writable)            — source: compressed token owner/leaf PDA
/// [1] mint        (writable)            — Token-2022 mint (supply decrement)
/// [2] authority   (readonly, signer)    — who signs (same pubkey as [0], deduped by runtime)
/// [3] system_program (readonly)         — Solana System Program
/// [4] fee_payer   (writable, signer)    — pays Light Protocol rent/fees
/// [5+] remaining_accounts               — Light system accounts (Merkle tree, nullifier queue, noop)
/// ```
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn cpi_compressed_burn<'a>(
    _compressed_token_program: &'a AccountView,
    payer: &'a AccountView,
    authority: &'a AccountView,
    mint: &'a AccountView,
    system_program: &'a AccountView,
    amount: u64,
    remaining_accounts: &'a [AccountView],
    signers: &[Signer],
) -> Result<(), ProgramError> {
    let data = build_compressed_burn_data(amount);
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();

    let mut account_metas = Vec::with_capacity(5 + remaining_accounts.len());
    account_metas.push(InstructionAccount::writable(authority.address()));         // [0] source (= authority, writable)
    account_metas.push(InstructionAccount::writable(mint.address()));              // [1] mint (writable — supply decrement)
    account_metas.push(InstructionAccount::readonly_signer(authority.address())); // [2] authority (readonly_signer, deduped w/ [0])
    account_metas.push(InstructionAccount::readonly(system_program.address()));   // [3] system_program
    account_metas.push(InstructionAccount::writable_signer(payer.address()));     // [4] fee_payer
    for acct in remaining_accounts {
        let meta = match (acct.is_writable(), acct.is_signer()) {
            (true, true)  => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _             => InstructionAccount::readonly(acct.address()),
        };
        account_metas.push(meta);
    }

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: &data,
    };

    // Account views must match instruction.accounts 1:1 (no program account).
    // See cpi_decompress_to_spl for detailed explanation.
    let mut account_views: Vec<&AccountView> = Vec::with_capacity(5 + remaining_accounts.len());
    account_views.push(authority);       // [0] source
    account_views.push(mint);            // [1] mint
    account_views.push(authority);       // [2] authority (same ref — runtime deduplicates)
    account_views.push(system_program);  // [3] system_program
    account_views.push(payer);           // [4] fee_payer
    account_views.extend(remaining_accounts.iter());

    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, signers)?;
    Ok(())
}

// ── SPL Interface PDA Derivation ──────────────────────────────────────────────

/// Derive the Light SPL interface PDA address and bump.
///
/// Seeds: `[b"pool", mint_key]` on the Light cToken program
/// (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`).
///
/// The bump is required by the cToken program's `Compression` instruction data.
/// Call this during `transfer_from_pool` processing to validate the passed-in
/// `spl_interface_pda` account and extract the bump for the CPI call.
pub fn derive_spl_interface_pda(mint_key: &[u8; 32]) -> (Address, u8) {
    let light_ctoken: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    Address::find_program_address(&[b"pool", mint_key.as_ref()], &light_ctoken)
}


// ── Unit Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_compress_all_data ──────────────────────────────────────────────

    #[test]
    fn test_build_compress_all_data_total_length_is_42() {
        let data = build_compress_all_data(&[0u8; 32]);
        assert_eq!(data.len(), 42, "instruction data must be exactly 42 bytes");
    }

    #[test]
    fn test_build_compress_all_data_discriminator_matches_anchor_sha256() {
        let data = build_compress_all_data(&[0u8; 32]);
        assert_eq!(
            &data[0..8],
            &COMPRESS_SPL_TOKEN_ACCOUNT_DISC,
            "first 8 bytes must be COMPRESS_SPL_TOKEN_ACCOUNT_DISC"
        );
    }

    #[test]
    fn test_build_compress_all_data_owner_encoded_at_bytes_8_to_40() {
        let owner = [0xABu8; 32];
        let data = build_compress_all_data(&owner);
        assert_eq!(&data[8..40], owner.as_ref(), "owner pubkey at [8..40]");
    }

    #[test]
    fn test_build_compress_all_data_remaining_amount_is_none() {
        let data = build_compress_all_data(&[0u8; 32]);
        assert_eq!(data[40], 0x00, "remaining_amount: None tag = 0x00");
    }

    #[test]
    fn test_build_compress_all_data_cpi_context_is_none() {
        let data = build_compress_all_data(&[0u8; 32]);
        assert_eq!(data[41], 0x00, "cpi_context: None = 0x00");
    }

    #[test]
    fn test_build_compress_all_data_different_owners_produce_different_data() {
        let a = build_compress_all_data(&[0xAAu8; 32]);
        let b = build_compress_all_data(&[0xBBu8; 32]);
        assert_ne!(&a[8..40], &b[8..40], "different owners must differ in owner field");
        assert_eq!(&a[0..8], &b[0..8], "discriminator must be identical");
    }

    #[test]
    fn test_build_compress_all_data_is_deterministic() {
        let owner = [0x11u8; 32];
        let a = build_compress_all_data(&owner);
        let b = build_compress_all_data(&owner);
        assert_eq!(a, b, "same owner must yield identical data");
    }

    // ── build_compress_with_remaining_data ───────────────────────────────────

    #[test]
    fn test_build_compress_with_remaining_data_total_length_is_50() {
        let data = build_compress_with_remaining_data(&[0u8; 32], 0);
        assert_eq!(data.len(), 50, "instruction data must be exactly 50 bytes");
    }

    #[test]
    fn test_build_compress_with_remaining_data_discriminator_matches_anchor_sha256() {
        let data = build_compress_with_remaining_data(&[0u8; 32], 0);
        assert_eq!(
            &data[0..8],
            &COMPRESS_SPL_TOKEN_ACCOUNT_DISC,
            "first 8 bytes must be COMPRESS_SPL_TOKEN_ACCOUNT_DISC"
        );
    }

    #[test]
    fn test_build_compress_with_remaining_data_owner_encoded_at_bytes_8_to_40() {
        let owner = [0xCDu8; 32];
        let data = build_compress_with_remaining_data(&owner, 999);
        assert_eq!(&data[8..40], owner.as_ref(), "owner pubkey at [8..40]");
    }

    #[test]
    fn test_build_compress_with_remaining_data_some_tag_at_byte_40() {
        let data = build_compress_with_remaining_data(&[0u8; 32], 42_000_000);
        assert_eq!(data[40], 0x01, "remaining_amount: Some tag = 0x01");
    }

    #[test]
    fn test_build_compress_with_remaining_data_value_encoded_as_u64_le() {
        let remaining = 5_000_000_000u64; // 5,000 ZUPY
        let data = build_compress_with_remaining_data(&[0u8; 32], remaining);
        let encoded = u64::from_le_bytes(data[41..49].try_into().unwrap());
        assert_eq!(encoded, remaining, "remaining_amount value (u64 LE) at [41..49]");
    }

    #[test]
    fn test_build_compress_with_remaining_data_cpi_context_is_none() {
        let data = build_compress_with_remaining_data(&[0u8; 32], 1_000);
        assert_eq!(data[49], 0x00, "cpi_context: None = 0x00");
    }

    #[test]
    fn test_build_compress_with_remaining_data_zero_remaining() {
        let data = build_compress_with_remaining_data(&[0u8; 32], 0);
        assert_eq!(data[40], 0x01, "Some tag present even for zero");
        let encoded = u64::from_le_bytes(data[41..49].try_into().unwrap());
        assert_eq!(encoded, 0, "remaining = 0 encoded as 8 zero bytes");
    }

    #[test]
    fn test_build_compress_with_remaining_data_max_u64() {
        let data = build_compress_with_remaining_data(&[0u8; 32], u64::MAX);
        let encoded = u64::from_le_bytes(data[41..49].try_into().unwrap());
        assert_eq!(encoded, u64::MAX, "handles u64::MAX without truncation");
    }

    #[test]
    fn test_build_compress_with_remaining_data_is_deterministic() {
        let owner = [0x22u8; 32];
        let a = build_compress_with_remaining_data(&owner, 500_000);
        let b = build_compress_with_remaining_data(&owner, 500_000);
        assert_eq!(a, b, "same inputs must yield identical data");
    }

    #[test]
    fn test_build_compress_with_remaining_differs_from_compress_all() {
        let owner = [0x33u8; 32];
        let all_data = build_compress_all_data(&owner);
        let partial_data = build_compress_with_remaining_data(&owner, 1_000);
        // Discriminator same, owner same, but remaining_amount byte differs
        assert_eq!(&all_data[0..8], &partial_data[0..8], "same discriminator");
        assert_eq!(&all_data[8..40], &partial_data[8..40], "same owner");
        assert_ne!(all_data[40], partial_data[40], "None(0) vs Some(1) at byte [40]");
        assert_ne!(all_data.len(), partial_data.len(), "42 bytes vs 50 bytes");
    }

    // ── derive_spl_interface_pda ──────────────────────────────────────────

    #[test]
    fn test_derive_spl_interface_pda_bump_is_canonical_pda_bump() {
        // Any valid mint key should produce a canonical bump (1–255)
        let mint_key = [0x42u8; 32]; // arbitrary
        let (_, bump) = derive_spl_interface_pda(&mint_key);
        assert!(bump >= 1, "PDA bump must be >= 1 (canonical bump always < 255)");
        assert!(bump <= 255, "PDA bump must fit in u8");
    }

    #[test]
    fn test_derive_spl_interface_pda_different_mints_yield_different_pdas() {
        let mint_a = [0xAAu8; 32];
        let mint_b = [0xBBu8; 32];
        let (pda_a, _) = derive_spl_interface_pda(&mint_a);
        let (pda_b, _) = derive_spl_interface_pda(&mint_b);
        assert_ne!(pda_a, pda_b, "different mints must yield different spl_interface PDAs");
    }

    #[test]
    fn test_derive_spl_interface_pda_is_deterministic() {
        let mint_key = [0x11u8; 32];
        let (pda1, bump1) = derive_spl_interface_pda(&mint_key);
        let (pda2, bump2) = derive_spl_interface_pda(&mint_key);
        assert_eq!(pda1, pda2, "same mint must yield same PDA");
        assert_eq!(bump1, bump2, "same mint must yield same bump");
    }

    #[test]
    fn test_derive_spl_interface_pda_address_is_not_all_zeros() {
        let mint_key = [0x55u8; 32];
        let (pda, _) = derive_spl_interface_pda(&mint_key);
        let pda_bytes: &[u8] = pda.as_ref();
        assert_ne!(pda_bytes, &[0u8; 32], "spl_interface PDA must not be all-zeros");
    }

    // ── build_compressed_transfer_data ───────────────────────────────────

    #[test]
    fn test_build_compressed_transfer_data_discriminator_is_3() {
        let data = build_compressed_transfer_data(1_000_000);
        assert_eq!(data[0], 3u8, "first byte must be Transfer discriminator (3)");
    }

    #[test]
    fn test_build_compressed_transfer_data_total_length_is_9() {
        let data = build_compressed_transfer_data(0);
        assert_eq!(data.len(), 9, "instruction data must be exactly 9 bytes");
    }

    #[test]
    fn test_build_compressed_transfer_data_amount_encoded_correctly() {
        let amount = 42_000_000u64; // 42 ZUPY (6 decimals)
        let data = build_compressed_transfer_data(amount);
        let encoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(encoded, amount, "amount (u64 LE) at bytes [1..9]");
    }

    #[test]
    fn test_build_compressed_transfer_data_zero_amount() {
        let data = build_compressed_transfer_data(0);
        assert_eq!(&data[1..9], &[0u8; 8], "amount=0 encodes as 8 zero bytes");
    }

    #[test]
    fn test_build_compressed_transfer_data_max_amount_u64() {
        let data = build_compressed_transfer_data(u64::MAX);
        let encoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(encoded, u64::MAX, "handles u64::MAX without truncation");
    }

    #[test]
    fn test_build_compressed_transfer_data_is_deterministic() {
        let a = build_compressed_transfer_data(99_000);
        let b = build_compressed_transfer_data(99_000);
        assert_eq!(a, b, "same amount must yield identical instruction data");
    }

    #[test]
    fn test_build_compressed_transfer_data_different_amounts_differ() {
        let a = build_compressed_transfer_data(1_000);
        let b = build_compressed_transfer_data(2_000);
        assert_ne!(a, b, "different amounts must yield different instruction data");
    }

    // ── build_compressed_burn_data ────────────────────────────────────────

    #[test]
    fn test_build_compressed_burn_data_discriminator_is_8() {
        let data = build_compressed_burn_data(1_000_000);
        assert_eq!(data[0], 8u8, "first byte must be Burn discriminator (8)");
    }

    #[test]
    fn test_build_compressed_burn_data_total_length_is_9() {
        let data = build_compressed_burn_data(0);
        assert_eq!(data.len(), 9, "instruction data must be exactly 9 bytes");
    }

    #[test]
    fn test_build_compressed_burn_data_amount_encoded_correctly() {
        let amount = 83_333u64; // typical burn portion
        let data = build_compressed_burn_data(amount);
        let encoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(encoded, amount, "amount (u64 LE) at bytes [1..9]");
    }

    #[test]
    fn test_build_compressed_burn_data_zero_amount() {
        let data = build_compressed_burn_data(0);
        assert_eq!(&data[1..9], &[0u8; 8], "amount=0 encodes as 8 zero bytes");
    }

    #[test]
    fn test_build_compressed_burn_data_max_amount_u64() {
        let data = build_compressed_burn_data(u64::MAX);
        let encoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        assert_eq!(encoded, u64::MAX, "handles u64::MAX without truncation");
    }

    #[test]
    fn test_build_compressed_burn_data_is_deterministic() {
        let a = build_compressed_burn_data(42_000);
        let b = build_compressed_burn_data(42_000);
        assert_eq!(a, b, "same amount must yield identical instruction data");
    }

    #[test]
    fn test_build_compressed_burn_data_different_amounts_differ() {
        let a = build_compressed_burn_data(1_000);
        let b = build_compressed_burn_data(2_000);
        assert_ne!(a, b, "different amounts must yield different instruction data");
    }

    #[test]
    fn test_build_compressed_burn_data_discriminator_differs_from_transfer() {
        let burn_data = build_compressed_burn_data(500);
        let transfer_data = build_compressed_transfer_data(500);
        assert_ne!(
            burn_data[0], transfer_data[0],
            "Burn (8) and Transfer (3) discriminators must differ"
        );
        assert_eq!(burn_data[0], 8, "Burn disc must be 8");
        assert_eq!(transfer_data[0], 3, "Transfer disc must be 3");
    }

    #[test]
    fn test_build_compressed_burn_data_amount_field_matches_transfer_layout() {
        // Both Burn and Transfer encode amount at bytes [1..9] (u64 LE)
        let amount = 999_999u64;
        let burn_data = build_compressed_burn_data(amount);
        let transfer_data = build_compressed_transfer_data(amount);
        assert_eq!(
            &burn_data[1..9], &transfer_data[1..9],
            "amount field layout must be identical between Burn and Transfer"
        );
    }

    // ── build_decompress_to_spl_data ─────────────────────────────────────────

    #[test]
    /// Discriminator confirmed correct from light-token-pinocchio 0.22.0 SDK source
    /// (transfer_to_spl.rs: `TRANSFER2_DISCRIMINATOR: u8 = 101`).
    fn test_build_decompress_to_spl_data_discriminator_is_101() {
        let data = build_decompress_to_spl_data(1_000_000, 255);
        assert_eq!(data[0], TRANSFER2_DISC, "first byte must be Transfer2 discriminator (101)");
        assert_eq!(data[0], 101);
    }

    #[test]
    fn test_build_decompress_to_spl_data_total_length_is_59() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data.len(), 59, "instruction data must be exactly 59 bytes");
    }

    #[test]
    fn test_build_decompress_to_spl_data_max_top_up_is_u16_max() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[6], 0xFF, "max_top_up low byte");
        assert_eq!(data[7], 0xFF, "max_top_up high byte (u16::MAX)");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compressions_is_some_with_two_entries() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[9], 1, "compressions: Some = 1");
        assert_eq!(&data[10..14], &[2, 0, 0, 0], "vec len = 2 (u32 LE)");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_mode_is_decompress() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[14], 1, "Compression 0 mode: Decompress = 1");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_amount_encoded_correctly() {
        let amount = 42_000_000u64; // 42 ZUPY
        let data = build_decompress_to_spl_data(amount, 0);
        let encoded = u64::from_le_bytes(data[15..23].try_into().unwrap());
        assert_eq!(encoded, amount, "Compression 0 amount (u64 LE) at [15..23]");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_account_indices() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[23], 0, "mint index = packed[0]");
        assert_eq!(data[24], 1, "source_or_recipient = packed[1] (pool_ata, SPL destination)");
        assert_eq!(data[25], 0, "authority = 0 (UNUSED for decompress_spl)");
        assert_eq!(data[26], 3, "pool_account_index = packed[3] (spl_interface_pda)");
        assert_eq!(data[27], 0, "pool_index = 0");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_bump_stored_correctly() {
        let bump: u8 = 251;
        let data = build_decompress_to_spl_data(0, bump);
        assert_eq!(data[28], bump, "spl_interface_pda bump stored at [28]");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_decimals_is_token_decimals() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[29], TOKEN_DECIMALS, "Compression 0 decimals = TOKEN_DECIMALS (6)");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression1_mode_is_compress() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[30], 0, "Compression 1 mode: Compress = 0");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression1_amount_equals_compression0_amount() {
        let amount = 5_000_000_000u64; // 5,000 ZUPY
        let data = build_decompress_to_spl_data(amount, 0);
        let c1_amount = u64::from_le_bytes(data[31..39].try_into().unwrap());
        assert_eq!(c1_amount, amount, "Compression 1 amount must equal Compression 0 amount");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression1_account_indices() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[39], 0, "Compression 1 mint index = packed[0]");
        assert_eq!(data[40], 2, "source_or_recipient = packed[2] (source PDA, compressed source)");
        assert_eq!(data[41], 2, "authority = packed[2] (source PDA, signer)");
        assert_eq!(data[42], 0, "pool_account_index = 0 (unused)");
        assert_eq!(data[43], 0, "pool_index = 0 (unused)");
        assert_eq!(data[44], 0, "bump = 0 (unused)");
        assert_eq!(data[45], 0, "decimals = 0 (unused)");
    }

    #[test]
    fn test_build_decompress_to_spl_data_trailing_fields_are_zero_or_none() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(data[46], 0, "proof: None");
        assert_eq!(&data[47..51], &[0, 0, 0, 0], "in_token_data: empty vec");
        assert_eq!(&data[51..55], &[0, 0, 0, 0], "out_token_data: empty vec");
        assert_eq!(&data[55..59], &[0, 0, 0, 0], "remaining Option fields: None");
    }

    #[test]
    fn test_build_decompress_to_spl_data_zero_amount_has_zero_amount_fields() {
        let data = build_decompress_to_spl_data(0, 0);
        assert_eq!(&data[15..23], &[0u8; 8], "amount=0 in Compression 0");
        assert_eq!(&data[31..39], &[0u8; 8], "amount=0 in Compression 1");
    }

    #[test]
    fn test_build_decompress_to_spl_data_max_amount_u64() {
        let amount = u64::MAX;
        let data = build_decompress_to_spl_data(amount, 0);
        let c0 = u64::from_le_bytes(data[15..23].try_into().unwrap());
        let c1 = u64::from_le_bytes(data[31..39].try_into().unwrap());
        assert_eq!(c0, u64::MAX, "Compression 0 handles u64::MAX");
        assert_eq!(c1, u64::MAX, "Compression 1 handles u64::MAX");
    }

    #[test]
    fn test_build_decompress_to_spl_data_compression0_mode_is_decompress_compression1_is_compress() {
        let data = build_decompress_to_spl_data(1_000, 0);
        assert_eq!(data[14], 1, "C0 mode: Decompress = 1");
        assert_eq!(data[30], 0, "C1 mode: Compress = 0");
    }

    // ── TRANSFER_V1_DISC ────────────────────────────────────────────────────

    #[test]
    fn test_transfer_v1_disc_matches_sha256_global_transfer() {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"global:transfer");
        let expected: [u8; 8] = hash[0..8].try_into().unwrap();
        assert_eq!(
            TRANSFER_V1_DISC, expected,
            "TRANSFER_V1_DISC must equal SHA256(\"global:transfer\")[0..8]"
        );
    }

    #[test]
    fn test_transfer_v1_disc_is_correct_bytes() {
        assert_eq!(
            TRANSFER_V1_DISC,
            [163, 52, 200, 231, 140, 3, 69, 186],
            "V1 TRANSFER disc must be [163, 52, 200, 231, 140, 3, 69, 186]"
        );
    }

    #[test]
    fn test_transfer_v1_disc_differs_from_compress_spl_disc() {
        assert_ne!(
            TRANSFER_V1_DISC, COMPRESS_SPL_TOKEN_ACCOUNT_DISC,
            "V1 TRANSFER and compress_spl_token_account must have different discriminators"
        );
    }

    // ── validate_v1_transfer_disc ───────────────────────────────────────────

    #[test]
    fn test_validate_v1_transfer_disc_valid_prefix_succeeds() {
        let mut data = Vec::from(TRANSFER_V1_DISC.as_slice());
        data.extend_from_slice(&[0u8; 50]); // Borsh payload
        assert!(validate_v1_transfer_disc(&data).is_ok());
    }

    #[test]
    fn test_validate_v1_transfer_disc_exactly_8_bytes_succeeds() {
        let data = TRANSFER_V1_DISC;
        assert!(validate_v1_transfer_disc(&data).is_ok());
    }

    #[test]
    fn test_validate_v1_transfer_disc_wrong_prefix_fails() {
        let data = [0u8; 16]; // wrong disc
        assert_eq!(
            validate_v1_transfer_disc(&data),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn test_validate_v1_transfer_disc_compress_disc_rejected() {
        let mut data = Vec::from(COMPRESS_SPL_TOKEN_ACCOUNT_DISC.as_slice());
        data.extend_from_slice(&[0u8; 50]);
        assert_eq!(
            validate_v1_transfer_disc(&data),
            Err(ProgramError::InvalidInstructionData),
            "compress_spl_token_account disc must be rejected"
        );
    }

    #[test]
    fn test_validate_v1_transfer_disc_short_data_7_bytes_fails() {
        let data = [163, 52, 200, 231, 140, 3, 69]; // 7 bytes, 1 short
        assert_eq!(
            validate_v1_transfer_disc(&data),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn test_validate_v1_transfer_disc_empty_fails() {
        assert_eq!(
            validate_v1_transfer_disc(&[]),
            Err(ProgramError::InvalidInstructionData),
        );
    }

    #[test]
    fn test_validate_v1_transfer_disc_transfer2_disc_rejected() {
        // Transfer2 disc=101 as first byte, rest zeros — must fail
        let mut data = [0u8; 16];
        data[0] = TRANSFER2_DISC;
        assert_eq!(
            validate_v1_transfer_disc(&data),
            Err(ProgramError::InvalidInstructionData),
            "Transfer2 single-byte disc must be rejected (V1 expects 8-byte Anchor disc)"
        );
    }
}
