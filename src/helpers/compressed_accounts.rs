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
//! ## Mainnet V2 (Upgraded 2026-04-04 verified)
//!
//! Both **mainnet** and **devnet** now run cToken V2. Light Protocol upgraded
//! mainnet at slot ~405,926,389 (binary: 1.15MB, was 642KB V1).
//! Binary analysis confirmed: Transfer2, Decompress, CTokenBurn handlers present;
//! V1 Anchor dispatch (`global:transfer`) NOT found in mainnet binary.
//!
//! | Operation | Disc | Mainnet Status |
//! |-----------|------|----------------|
//! | `compress_spl_token_account` | 8-byte Anchor | **WORKS** |
//! | Transfer2 (decompress/transfer) | disc=101 | **WORKS** |
//! | Compressed transfer | disc=3 | **WORKS** |
//! | Burn | disc=8 | **WORKS** |
//!
//! All V2 operations are available on mainnet. The V1 CPI passthrough instructions
//! (`return_to_pool_v1`, `return_user_to_pool_v1`) are **DEPRECATED** — the V1
//! TRANSFER discriminator `[163,52,200,231,140,3,69,186]` is no longer present
//! in the mainnet binary. Use the native V2 instructions (`return_to_pool`,
//! `return_user_to_pool`) instead.
//!
//! ### Historical Note (pre-2026-04)
//!
//! Before slot ~405M, mainnet ran V1 (Anchor-based, 642KB, slot 351672434).
//! Transfer2 (disc=101) and Burn (disc=8) were BLOCKED, requiring V1 CPI
//! passthrough via `TRANSFER_V1_DISC`. See sprint-change-proposal-2026-02-19.md.

use pinocchio::AccountView;
use pinocchio::Address;
use pinocchio::cpi::Signer;
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};

use crate::constants::{LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, TOKEN_DECIMALS};
use crate::error::ZupyTokenError;
use crate::helpers::instruction_data::{parse_bool, parse_bytes, parse_u16, parse_u32, parse_u64, parse_u8};

/// Append each remaining account as an `InstructionAccount` meta, preserving its
/// writable/signer flags. Shared by every compressed-token CPI builder — dedups
/// the identical loop across the compress / transfer / burn paths.
#[inline(always)]
fn push_remaining_metas<'a>(metas: &mut Vec<InstructionAccount<'a>>, remaining: &'a [AccountView]) {
    for acct in remaining {
        let meta = match (acct.is_writable(), acct.is_signer()) {
            (true, true) => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _ => InstructionAccount::readonly(acct.address()),
        };
        metas.push(meta);
    }
}

/// Build instruction-account metas from CPI accounts, forcing `forced_signer` to
/// be a signer (needed for `invoke_signed`, where our program signs for a PDA
/// that is not a signer on the outer tx). Dedups the identical loop in the V1
/// passthrough transfer + return-to-pool paths.
#[inline(always)]
pub fn build_metas_forcing_signer<'a>(
    cpi_accounts: &'a [AccountView],
    forced_signer: &AccountView,
) -> Vec<InstructionAccount<'a>> {
    let mut metas = Vec::with_capacity(cpi_accounts.len());
    for acct in cpi_accounts {
        let force = acct.address() == forced_signer.address();
        let meta = match (acct.is_writable(), acct.is_signer() || force) {
            (true, true) => InstructionAccount::writable_signer(acct.address()),
            (true, false) => InstructionAccount::writable(acct.address()),
            (false, true) => InstructionAccount::readonly_signer(acct.address()),
            _ => InstructionAccount::readonly(acct.address()),
        };
        metas.push(meta);
    }
    metas
}

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

/// DEPRECATED (2026-04-04): Mainnet cToken upgraded to V2 (slot ~405M).
/// V1 Anchor dispatch (`global:transfer`) no longer present in mainnet binary.
/// Use Transfer2 (disc=101) via the native `return_to_pool` / `return_user_to_pool`
/// instructions instead.
///
/// V1 TRANSFER discriminator for the Light cToken program (Anchor 8-byte).
/// = SHA256("global:transfer")[0..8]
/// Was used by mainnet V1 cToken for ALL transfer operations.
/// Retained for the `return_*_v1` passthrough instructions (also deprecated).
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

// ── Packed account indices for the decompress path ────────────────────────────
//
// `packed_accounts` are the accounts AFTER the 7 light-system accounts (see
// `cpi_decompress_to_spl`). Trees and queues MUST come first — the SDK states it
// outright (`light-compressed-token-sdk` `transfer2/cpi_accounts.rs:37`: "Trees
// and queues must be first") and `pack_merkle_context` assigns their indices by
// inserting tree then queue before anything else.
const PACKED_TREE: u8 = 0;
const PACKED_QUEUE: u8 = 1;
const PACKED_OWNER: u8 = 2; // entity PDA — the LEAF OWNER (readonly signer)
const PACKED_MINT: u8 = 3;
const PACKED_POOL_ATA: u8 = 4; // SPL destination
const PACKED_SPL_INTERFACE: u8 = 5; // omnibus (holds the locked SPL)

/// Total size of the Transfer2 payload built by [`build_decompress_to_spl_data`].
pub(crate) const DECOMPRESS_TO_SPL_DATA_LEN: usize = 206;

/// Everything the Transfer2 decompress payload needs that only the client knows.
///
/// The Photon-derived fields (`version`, `leaf_index`, `root_index`,
/// `prove_by_index`, `leaf_amount`, `proof`) cannot be computed on-chain — they
/// describe a Merkle leaf and its ZK proof, so they must arrive over the wire.
pub struct DecompressToSplParams<'a> {
    /// Tokens to release from the omnibus into the pool ATA.
    pub amount: u64,
    /// FULL balance of the leaf being spent (not `amount`) — seeds the sum check.
    pub leaf_amount: u64,
    /// Bump of the `spl_interface_pda` (omnibus).
    pub spl_bump: u8,
    /// `TokenDataVersion` of THIS leaf. Read it per leaf; never hardcode — it
    /// selects the hash algorithm (V1 hashes the amount LE, V2 BE), so a wrong
    /// value yields a leaf hash that misses the tree and the proof is rejected.
    pub version: u8,
    /// Leaf index within the Merkle tree.
    pub leaf_index: u32,
    /// Index of the root the proof was generated against. Volatile — the client
    /// must fetch it fresh per attempt and never cache it.
    pub root_index: u16,
    /// Whether the leaf is provable by index (then the ZK proof is redundant).
    pub prove_by_index: bool,
    /// Groth16 validity proof from Photon: a[32] | b[64] | c[32].
    pub proof: &'a [u8; 128],
}

/// Builds the 206-byte Borsh-encoded `CompressedTokenInstructionDataTransfer2`
/// that decompresses part of a compressed leaf into the pool ATA.
///
/// # Why this shape (and why the old one could never work)
///
/// The previous builder emitted TWO compressions — `[Decompress, Compress]` —
/// with an EMPTY `in_token_data`, and failed 100% of the time with cToken error
/// **6005 = `SumCheckFailed`** ("Cannot decompress if no balance exists").
///
/// Two independent defects, one design error:
///
/// 1. **Sum check.** The cToken tracks per-mint balances in an in-memory
///    `ArrayMap` seeded ONLY by `in_token_data`. With no inputs the map is empty,
///    so the first `Decompress` finds no entry for the mint and bails — before
///    touching a single account, in ~3k CU. The message names neither the
///    omnibus (which holds 704k Z$) nor the company leaves (which exist).
/// 2. **`Compress` cannot spend a leaf.** `CompressionMode::Compress` moves
///    tokens out of an on-chain ctoken ACCOUNT into the pool. The entity PDA is
///    NOT an account — it is only the `owner` field of Merkle leaves. A leaf is
///    spent by declaring it in `in_token_data` with a validity proof, which is
///    exactly what this builder now does.
///
/// Sum check here: `+leaf_amount − amount − (leaf_amount − amount) = 0`.
/// Because `in_token_data` seeds the map, compression ORDER is no longer
/// load-bearing.
///
/// # Layout (verified byte-for-byte by a clean mainnet simulation)
///
/// ```text
/// [  0]      disc = 101
/// [  1..  5] header flags = 0
/// [  5]      output_queue = PACKED_TREE — an INDEX, and it points at the TREE,
///            not the queue: the public state tree is StateV1 (legacy), whose
///            outputs are appended to the tree itself. Pointing it at the queue
///            fails with 6042.
/// [  6..  8] max_top_up = u16::MAX (LE)
/// [  8]      cpi_context = None
/// [  9.. 14] compressions = Some, len = 1 (u32 LE)
/// [ 14.. 30] Compression: decompress_spl(amount, mint, pool_ata, omnibus, 0, bump, 6)
/// [ 30..159] proof = Some + a[32] b[64] c[32]
/// [159..185] in_token_data = len 1 + MultiInputTokenDataWithContext (22B)
/// [185..202] out_token_data = len 1 + MultiTokenTransferOutputData (13B) — change
/// [202..206] in_lamports / out_lamports / in_tlv / out_tlv = None
/// ```
///
/// Vec lengths are u32 LE (not ULEB): `ZeroCopySliceBorsh = ZeroCopySlice<U32,…>`.
/// No padding despite `#[repr(C)]` — the zero-copy derive is Borsh-compatible and
/// the meta structs are `Unaligned`.
///
/// # Caller obligation
///
/// This instruction costs ~211k CU against a v1 tree, over Solana's 200k default.
/// The sender MUST prepend a `ComputeBudget` limit or the tx dies with
/// `ProgramFailedToComplete` even though these bytes are correct.
#[inline]
pub(crate) fn build_decompress_to_spl_data(
    params: &DecompressToSplParams,
) -> [u8; DECOMPRESS_TO_SPL_DATA_LEN] {
    let mut d = [0u8; DECOMPRESS_TO_SPL_DATA_LEN];

    // ── Header ───────────────────────────────────────────────────────────────
    d[0] = TRANSFER2_DISC;
    // d[1..5] = with_transaction_hash / lamports-change placeholders = 0
    d[5] = PACKED_TREE; // output_queue (see doc: index, and it is the TREE)
    d[6] = 0xFF; // max_top_up = u16::MAX
    d[7] = 0xFF;
    // d[8] = cpi_context: None

    // ── compressions: Some(vec![decompress_spl]) ─────────────────────────────
    d[9] = 1; // Some
    d[10] = 1; // vec len = 1 (u32 LE, high bytes stay 0)
    d[14] = 1; // mode: CompressionMode::Decompress
    d[15..23].copy_from_slice(&params.amount.to_le_bytes());
    d[23] = PACKED_MINT;
    d[24] = PACKED_POOL_ATA; // source_or_recipient = SPL destination
    // d[25] = authority: unused for decompress_spl
    d[26] = PACKED_SPL_INTERFACE; // pool_account_index = omnibus
    // d[27] = pool_index = 0
    d[28] = params.spl_bump;
    d[29] = TOKEN_DECIMALS;

    // ── proof: Some(CompressedProof) ─────────────────────────────────────────
    d[30] = 1; // Some
    d[31..159].copy_from_slice(params.proof.as_ref());

    // ── in_token_data: the leaf being spent (this is what seeds the sum check) ─
    d[159] = 1; // vec len = 1 (u32 LE)
    d[163] = PACKED_OWNER;
    d[164..172].copy_from_slice(&params.leaf_amount.to_le_bytes());
    // d[172] = has_delegate: false, d[173] = delegate: 0
    d[174] = PACKED_MINT;
    d[175] = params.version;
    d[176] = PACKED_TREE; // merkle_context.merkle_tree_pubkey_index
    d[177] = PACKED_QUEUE; // merkle_context.queue_pubkey_index
    d[178..182].copy_from_slice(&params.leaf_index.to_le_bytes());
    d[182] = params.prove_by_index as u8;
    d[183..185].copy_from_slice(&params.root_index.to_le_bytes());

    // ── out_token_data: the change leaf (leaf_amount - amount) ───────────────
    d[185] = 1; // vec len = 1 (u32 LE)
    d[189] = PACKED_OWNER;
    let change = params.leaf_amount.saturating_sub(params.amount);
    d[190..198].copy_from_slice(&change.to_le_bytes());
    // d[198] = has_delegate: false, d[199] = delegate: 0
    d[200] = PACKED_MINT;
    d[201] = params.version;
    // d[202..206] = in_lamports / out_lamports / in_tlv / out_tlv = None

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
    push_remaining_metas(&mut account_metas, remaining_accounts);

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

/// Wire size of the leaf/proof block parsed by [`parse_leaf_proof_fields`].
///
/// `leaf_amount(8) + version(1) + leaf_index(4) + root_index(2) + prove_by_index(1) + proof(128)`
pub const LEAF_PROOF_WIRE_LEN: usize = 144;

/// Parse the leaf + validity-proof block that every decompress instruction carries.
///
/// These values are Photon-derived and cannot be recomputed on-chain, so they
/// travel over the wire. Shared by `return_to_pool`, `return_user_to_pool` and
/// `withdraw_to_external` — all three spend a leaf via `cpi_decompress_to_spl`.
///
/// Returns the params (minus `amount`/`spl_bump`, which the caller owns) plus the
/// offset just past the block.
#[inline]
pub fn parse_leaf_proof_fields(
    data: &[u8],
    offset: usize,
) -> Result<(LeafProofFields<'_>, usize), ProgramError> {
    let leaf_amount = parse_u64(data, offset)?;
    let version = parse_u8(data, offset + 8)?;
    let leaf_index = parse_u32(data, offset + 9)?;
    let root_index = parse_u16(data, offset + 13)?;
    let prove_by_index = parse_bool(data, offset + 15)?;
    let (proof, next) = parse_bytes::<128>(data, offset + 16)?;
    Ok((
        LeafProofFields {
            leaf_amount,
            version,
            leaf_index,
            root_index,
            prove_by_index,
            proof,
        },
        next,
    ))
}

/// The Photon-derived half of [`DecompressToSplParams`], as it arrives on the wire.
pub struct LeafProofFields<'a> {
    pub leaf_amount: u64,
    pub version: u8,
    pub leaf_index: u32,
    pub root_index: u16,
    pub prove_by_index: bool,
    pub proof: &'a [u8; 128],
}

impl<'a> LeafProofFields<'a> {
    /// Combine the wire fields with the caller-owned `amount` and omnibus bump.
    #[inline]
    pub fn into_params(self, amount: u64, spl_bump: u8) -> DecompressToSplParams<'a> {
        DecompressToSplParams {
            amount,
            leaf_amount: self.leaf_amount,
            spl_bump,
            version: self.version,
            leaf_index: self.leaf_index,
            root_index: self.root_index,
            prove_by_index: self.prove_by_index,
            proof: self.proof,
        }
    }
}

/// The accounts a Transfer2 decompress CPI needs, in the order the cToken expects.
///
/// Grouped into a struct because the flat argument list crossed the point where
/// positional mistakes stop being caught by the type checker — every field here
/// is an `AccountView` and a swap would compile silently.
pub struct DecompressToSplAccounts<'a> {
    // ── Light system accounts (fixed prefix, indices 0..7) ────────────────────
    pub light_system_program: &'a AccountView,
    pub payer: &'a AccountView,
    pub compressed_token_authority: &'a AccountView,
    pub registered_program_pda: &'a AccountView,
    pub account_compression_authority: &'a AccountView,
    pub account_compression_program: &'a AccountView,
    pub system_program: &'a AccountView,
    // ── Packed accounts (indices 7.., see PACKED_* constants) ────────────────
    pub merkle_tree: &'a AccountView,
    pub output_queue: &'a AccountView,
    /// Entity PDA — the LEAF OWNER. Signs via `invoke_signed`.
    pub authority: &'a AccountView,
    pub mint: &'a AccountView,
    pub destination_spl: &'a AccountView,
    pub spl_interface_pda: &'a AccountView,
    pub spl_token_program: &'a AccountView,
}

/// CPI: Decompress part of a compressed leaf into a destination SPL ATA (pool_ata).
///
/// Used by `return_to_pool` and `return_user_to_pool`. Both spend a Merkle leaf
/// owned by an entity PDA, so both need the full ZK path — see
/// [`build_decompress_to_spl_data`] for why the old proof-free shape always
/// failed with 6005.
///
/// ## Account order passed to the cToken program
///
/// Declaring `in_token_data` flips `no_compressed_accounts` to false, which routes
/// the cToken through the light-system program. That path takes a DIFFERENT,
/// longer account prefix than the old compressions-only one: **packed accounts
/// start at index 7, not 2** (`light-compressed-token-sdk`
/// `transfer2/account_metas.rs`). `noop` is not part of it.
///
/// ```text
/// [0] light_system_program           (readonly)
/// [1] fee_payer                      (writable, signer)
/// [2] cpi_authority_pda              (readonly)
/// [3] registered_program_pda         (readonly)
/// [4] account_compression_authority  (readonly)
/// [5] account_compression_program    (readonly)
/// [6] system_program                 (readonly)
/// packed (trees and queues first):
/// [7]  merkle_tree                   (writable)          → packed[0]
/// [8]  output_queue                  (writable)          → packed[1]
/// [9]  authority (entity PDA)        (readonly, signer)  → packed[2]  LEAF OWNER
/// [10] mint                          (readonly)          → packed[3]
/// [11] destination_spl (pool_ata)    (writable)          → packed[4]
/// [12] spl_interface_pda             (writable)          → packed[5]
/// [13] spl_token_program             (readonly)          → packed[6]
/// ```
///
/// The entity PDA's role changed but its signature did not: it used to be the
/// `source` of a `Compress`, it is now the owner of the input leaf, still marked
/// `readonly_signer` and still signed for with the same `[seed, id, bump]` seeds.
/// Rejeita cedo, por 1 CU, o que o sum check do cToken rejeitaria por ~211k.
///
/// O troco vai para a wire como `leaf_amount.saturating_sub(amount)`. Quando
/// `amount > leaf_amount` a subtração **satura em 0** em vez de estourar, e a
/// instrução sai montada e aparentemente sadia: o sum check
/// `+leaf_amount − amount − troco` fica negativo e quem reprova é a chain, com
/// um erro da família do cToken — a mesma classe de erro opaco que deixou o
/// `return_to_pool` quatro meses parado. Um `>` aqui custa uma comparação.
///
/// `amount == leaf_amount` é legítimo: gasta a folha inteira, troco zero.
#[inline]
pub(crate) fn validate_decompress_amounts(leaf_amount: u64, amount: u64) -> Result<(), ProgramError> {
    if amount > leaf_amount {
        return Err(ZupyTokenError::InsufficientBalance.into());
    }
    Ok(())
}

#[inline(always)]
pub fn cpi_decompress_to_spl(
    accounts: &DecompressToSplAccounts,
    params: &DecompressToSplParams,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    validate_decompress_amounts(params.leaf_amount, params.amount)?;
    let data = build_decompress_to_spl_data(params);
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();

    let account_metas = [
        InstructionAccount::readonly(accounts.light_system_program.address()), // [0]
        InstructionAccount::writable_signer(accounts.payer.address()),         // [1]
        InstructionAccount::readonly(accounts.compressed_token_authority.address()), // [2]
        InstructionAccount::readonly(accounts.registered_program_pda.address()), // [3]
        InstructionAccount::readonly(accounts.account_compression_authority.address()), // [4]
        InstructionAccount::readonly(accounts.account_compression_program.address()), // [5]
        InstructionAccount::readonly(accounts.system_program.address()),      // [6]
        InstructionAccount::writable(accounts.merkle_tree.address()),         // packed[0]
        InstructionAccount::writable(accounts.output_queue.address()),        // packed[1]
        InstructionAccount::readonly_signer(accounts.authority.address()),    // packed[2]
        InstructionAccount::readonly(accounts.mint.address()),                // packed[3]
        InstructionAccount::writable(accounts.destination_spl.address()),     // packed[4]
        InstructionAccount::writable(accounts.spl_interface_pda.address()),   // packed[5]
        InstructionAccount::readonly(accounts.spl_token_program.address()),   // packed[6]
    ];

    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: &data,
    };

    // Account views must match instruction.accounts 1:1 (no program account).
    // Pinocchio 0.10 resolves the CPI target from InstructionView.program_id;
    // including the program here would shift every index by one.
    let account_views: [&AccountView; 14] = [
        accounts.light_system_program,
        accounts.payer,
        accounts.compressed_token_authority,
        accounts.registered_program_pda,
        accounts.account_compression_authority,
        accounts.account_compression_program,
        accounts.system_program,
        accounts.merkle_tree,
        accounts.output_queue,
        accounts.authority,
        accounts.mint,
        accounts.destination_spl,
        accounts.spl_interface_pda,
        accounts.spl_token_program,
    ];

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
    push_remaining_metas(&mut account_metas, remaining_accounts);

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
    //
    // GR23 — the previous 19 tests here pinned the OLD 59-byte shape: two
    // compressions `[Decompress, Compress]`, `proof: None`, empty in/out token
    // data, packed base 2. They are deleted rather than adapted because their
    // premise was proven impossible, not merely outdated: that shape can never
    // succeed (cToken 6005 = SumCheckFailed, 100% of the time in production).
    // Keeping them would pin a contract that does not exist.
    //
    // The expectations below are anchored to a CLEAN mainnet simulation
    // (`err: null`, 210.792 CU) against the real cToken and the real leaves.

    /// Field values from the proven mainnet simulation (Ettus Motel, 1 Z$ debit).
    fn proven_params(proof: &[u8; 128]) -> DecompressToSplParams<'_> {
        DecompressToSplParams {
            amount: 1_000_000,          // 1 Z$
            leaf_amount: 3_943_000_000, // full balance of the spent leaf
            spl_bump: 255,
            version: 1, // V1 — read from the leaf discriminator, never hardcoded
            leaf_index: 59_990_408,
            root_index: 1634,
            prove_by_index: false,
            proof,
        }
    }

    #[test]
    fn test_build_decompress_to_spl_data_total_length_is_206() {
        let p = [7u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(data.len(), DECOMPRESS_TO_SPL_DATA_LEN);
        assert_eq!(data.len(), 206, "proven layout is 206 bytes");
    }

    #[test]
    fn test_build_decompress_to_spl_data_discriminator_is_101() {
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(data[0], TRANSFER2_DISC);
        assert_eq!(data[0], 101);
    }

    #[test]
    fn test_output_queue_points_at_the_tree_not_the_queue() {
        // The public state tree is StateV1 (legacy): outputs are appended to the
        // tree itself. Pointing output_queue at the queue fails with 6042 —
        // verified by simulation.
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(data[5], PACKED_TREE, "output_queue must be the TREE index");
        assert_ne!(data[5], PACKED_QUEUE, "pointing at the queue yields 6042");
    }

    #[test]
    fn test_max_top_up_is_u16_max() {
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(&data[6..8], &[0xFF, 0xFF]);
    }

    #[test]
    fn test_exactly_one_compression_and_it_is_decompress() {
        // The old builder emitted two ([Decompress, Compress]); the `Compress`
        // entry could never spend a leaf (the PDA is not an account) and the
        // empty mint_sums map made the Decompress fail the sum check first.
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(data[9], 1, "compressions: Some");
        assert_eq!(&data[10..14], &[1, 0, 0, 0], "vec len = 1 (u32 LE), not 2");
        assert_eq!(data[14], 1, "mode = CompressionMode::Decompress");
    }

    #[test]
    fn test_compression_amount_and_indices() {
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(
            u64::from_le_bytes(data[15..23].try_into().unwrap()),
            1_000_000,
        );
        assert_eq!(data[23], PACKED_MINT);
        assert_eq!(data[24], PACKED_POOL_ATA, "source_or_recipient = SPL dest");
        assert_eq!(data[25], 0, "authority unused for decompress_spl");
        assert_eq!(data[26], PACKED_SPL_INTERFACE, "pool_account_index = omnibus");
        assert_eq!(data[27], 0, "pool_index = 0");
        assert_eq!(data[28], 255, "spl_interface_pda bump");
        assert_eq!(data[29], TOKEN_DECIMALS);
    }

    #[test]
    fn test_proof_is_some_and_copied_verbatim() {
        let mut proof = [0u8; 128];
        for (i, b) in proof.iter_mut().enumerate() {
            *b = i as u8;
        }
        let data = build_decompress_to_spl_data(&proven_params(&proof));
        assert_eq!(data[30], 1, "proof: Some — the sum check needs the leaf proven");
        assert_eq!(&data[31..159], proof.as_ref());
    }

    #[test]
    fn test_in_token_data_declares_the_leaf() {
        // This is the actual fix: in_token_data is the ONLY thing that seeds the
        // cToken's per-mint balance map. Empty => 6005 regardless of real balances.
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(&data[159..163], &[1, 0, 0, 0], "in_token_data len = 1");
        assert_eq!(data[163], PACKED_OWNER, "leaf owner = entity PDA");
        assert_eq!(
            u64::from_le_bytes(data[164..172].try_into().unwrap()),
            3_943_000_000,
            "must be the FULL leaf amount, not the debit amount",
        );
        assert_eq!(data[172], 0, "has_delegate = false");
        assert_eq!(data[173], 0, "delegate = 0");
        assert_eq!(data[174], PACKED_MINT);
        assert_eq!(data[175], 1, "version = V1");
        assert_eq!(data[176], PACKED_TREE, "merkle_tree_pubkey_index");
        assert_eq!(data[177], PACKED_QUEUE, "queue_pubkey_index");
        assert_eq!(
            u32::from_le_bytes(data[178..182].try_into().unwrap()),
            59_990_408,
        );
        assert_eq!(data[182], 0, "prove_by_index = false");
        assert_eq!(u16::from_le_bytes(data[183..185].try_into().unwrap()), 1634);
    }

    #[test]
    fn test_out_token_data_is_the_change_leaf() {
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(&data[185..189], &[1, 0, 0, 0], "out_token_data len = 1");
        assert_eq!(data[189], PACKED_OWNER, "change returns to the same owner");
        assert_eq!(
            u64::from_le_bytes(data[190..198].try_into().unwrap()),
            3_943_000_000 - 1_000_000,
            "change = leaf_amount - amount",
        );
        assert_eq!(data[200], PACKED_MINT);
        assert_eq!(data[201], 1, "version must match the input leaf");
    }

    #[test]
    fn test_sum_check_balances_to_zero() {
        // +leaf_amount (input) - amount (decompressed) - change (output) = 0.
        // This identity is what 6005 was complaining about.
        let p = [0u8; 128];
        let params = proven_params(&p);
        let data = build_decompress_to_spl_data(&params);
        let decompressed = u64::from_le_bytes(data[15..23].try_into().unwrap());
        let input = u64::from_le_bytes(data[164..172].try_into().unwrap());
        let output = u64::from_le_bytes(data[190..198].try_into().unwrap());
        assert_eq!(input, decompressed + output, "sum check must net to zero");
    }

    #[test]
    fn test_version_is_carried_not_hardcoded() {
        // The version selects the leaf hash algorithm (V1 amount LE, V2 BE).
        // Simulation: version=2 on a V1 leaf => 6043 ProofVerificationFailed.
        let p = [0u8; 128];
        for v in [1u8, 2, 3] {
            let mut params = proven_params(&p);
            params.version = v;
            let data = build_decompress_to_spl_data(&params);
            assert_eq!(data[175], v, "in_token_data version");
            assert_eq!(data[201], v, "out_token_data version must match");
        }
    }

    // ── validate_decompress_amounts (guarda do sum check) ────────────────────

    #[test]
    fn test_decompress_amounts_ok_quando_amount_cabe_no_leaf() {
        assert!(validate_decompress_amounts(3_943_000_000, 1_000_000).is_ok());
    }

    #[test]
    fn test_decompress_amounts_ok_quando_gasta_o_leaf_inteiro() {
        // Troco zero e legitimo: gastar a folha toda fecha o sum check em 0.
        assert!(validate_decompress_amounts(1_000_000, 1_000_000).is_ok());
    }

    #[test]
    fn test_decompress_amounts_rejeita_amount_maior_que_o_leaf() {
        // Sem a guarda o saturating_sub do troco satura em 0 e o sum check vira
        // +leaf - amount - 0 < 0: o cToken rejeita, mas so depois de ~211k CU.
        let err = validate_decompress_amounts(1_000_000, 1_000_001).unwrap_err();
        assert_eq!(err, ZupyTokenError::InsufficientBalance.into());
    }

    #[test]
    fn test_decompress_amounts_rejeita_leaf_zerado() {
        let err = validate_decompress_amounts(0, 1).unwrap_err();
        assert_eq!(err, ZupyTokenError::InsufficientBalance.into());
    }

    #[test]
    fn test_o_troco_satura_em_zero_e_por_isso_a_guarda_existe() {
        // Prova o motivo da guarda: HOJE o builder aceita amount > leaf_amount e
        // monta uma instrucao que ja se sabe invalida. O troco vira 0 em vez de
        // negativo, entao nada aqui reclama -- quem reclama e a chain, caro.
        let p = [0u8; 128];
        let mut params = proven_params(&p);
        params.amount = params.leaf_amount + 1;
        let data = build_decompress_to_spl_data(&params);
        let troco = u64::from_le_bytes(data[190..198].try_into().unwrap());
        assert_eq!(troco, 0, "saturating_sub mascara o estouro");
        let declarado = u64::from_le_bytes(data[15..23].try_into().unwrap());
        assert!(declarado > params.leaf_amount, "sai mais do que entrou");
    }

    #[test]
    fn test_prove_by_index_true_is_encoded() {
        let p = [0u8; 128];
        let mut params = proven_params(&p);
        params.prove_by_index = true;
        let data = build_decompress_to_spl_data(&params);
        assert_eq!(data[182], 1);
    }

    #[test]
    fn test_full_leaf_spend_leaves_zero_change() {
        let p = [0u8; 128];
        let mut params = proven_params(&p);
        params.amount = params.leaf_amount;
        let data = build_decompress_to_spl_data(&params);
        assert_eq!(&data[190..198], &[0u8; 8], "change = 0 when spending it all");
    }

    #[test]
    fn test_amount_over_leaf_amount_saturates_change_to_zero() {
        // Defence in depth: an over-spend must not wrap the change to ~u64::MAX
        // and mint tokens out of thin air. The cToken rejects it via the sum
        // check either way, but the builder must never emit that number.
        let p = [0u8; 128];
        let mut params = proven_params(&p);
        params.amount = params.leaf_amount + 1;
        let data = build_decompress_to_spl_data(&params);
        assert_eq!(&data[190..198], &[0u8; 8], "change saturates at 0, no wrap");
    }

    #[test]
    fn test_trailing_option_fields_are_none() {
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(
            &data[202..206],
            &[0, 0, 0, 0],
            "in_lamports / out_lamports / in_tlv / out_tlv = None",
        );
    }

    #[test]
    fn test_build_decompress_to_spl_data_is_deterministic() {
        let p = [3u8; 128];
        let a = build_decompress_to_spl_data(&proven_params(&p));
        let b = build_decompress_to_spl_data(&proven_params(&p));
        assert_eq!(a, b);
    }

    #[test]
    fn test_matches_the_proven_mainnet_bytes_exactly() {
        // Golden test: the exact payload that simulated clean on mainnet
        // (err: null). The proof is zeroed here since it is fetched per attempt;
        // every other byte is pinned.
        let p = [0u8; 128];
        let data = build_decompress_to_spl_data(&proven_params(&p));
        let expected_head: [u8; 30] = [
            101, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 1, 1, 0, 0, 0, // header + compressions len
            1, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0, // Decompress + amount 1_000_000 LE
            3, 4, 0, 5, 0, 255, 6, // mint, pool_ata, auth, omnibus, pool_index, bump, decimals
        ];
        assert_eq!(&data[0..30], &expected_head, "header + Compression[0]");

        let expected_in: [u8; 22] = [
            2, // owner = packed[2]
            0xc0, 0x67, 0x05, 0xeb, 0, 0, 0, 0, // leaf_amount 3_943_000_000 LE
            0, 0, // has_delegate, delegate
            3, 1, // mint, version=V1
            0, 1, // mt_index, queue_index
            0x88, 0x61, 0x93, 0x03, // leaf_index 59_990_408 LE
            0,    // prove_by_index
            0x62, 0x06, // root_index 1634 LE
        ];
        assert_eq!(&data[163..185], &expected_in, "MultiInputTokenDataWithContext");

        let expected_out: [u8; 13] = [
            2, // owner
            0x80, 0x25, 0xf6, 0xea, 0, 0, 0, 0, // change 3_942_000_000 LE
            0, 0, // has_delegate, delegate
            3, 1, // mint, version
        ];
        assert_eq!(&data[189..202], &expected_out, "MultiTokenTransferOutputData");
    }

    // ── parse_leaf_proof_fields ──────────────────────────────────────────────

    fn leaf_proof_wire() -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&3_943_000_000u64.to_le_bytes()); // leaf_amount
        w.push(1); // version
        w.extend_from_slice(&59_990_408u32.to_le_bytes()); // leaf_index
        w.extend_from_slice(&1634u16.to_le_bytes()); // root_index
        w.push(0); // prove_by_index
        w.extend_from_slice(&[9u8; 128]); // proof
        w
    }

    #[test]
    fn test_parse_leaf_proof_fields_roundtrips() {
        let wire = leaf_proof_wire();
        let (f, next) = parse_leaf_proof_fields(&wire, 0).unwrap();
        assert_eq!(f.leaf_amount, 3_943_000_000);
        assert_eq!(f.version, 1);
        assert_eq!(f.leaf_index, 59_990_408);
        assert_eq!(f.root_index, 1634);
        assert!(!f.prove_by_index);
        assert_eq!(f.proof, &[9u8; 128]);
        assert_eq!(next, LEAF_PROOF_WIRE_LEN, "offset lands past the block");
    }

    #[test]
    fn test_parse_leaf_proof_fields_honours_offset() {
        let mut wire = vec![0xAA; 17]; // entity_id + amount + bump prefix
        wire.extend_from_slice(&leaf_proof_wire());
        let (f, next) = parse_leaf_proof_fields(&wire, 17).unwrap();
        assert_eq!(f.leaf_index, 59_990_408);
        assert_eq!(next, 17 + LEAF_PROOF_WIRE_LEN);
    }

    #[test]
    fn test_parse_leaf_proof_fields_truncated_is_rejected() {
        let wire = leaf_proof_wire();
        for cut in [0usize, 8, 16, 143] {
            assert_eq!(
                parse_leaf_proof_fields(&wire[..cut], 0).err(),
                Some(ProgramError::InvalidInstructionData),
                "truncated at {cut} bytes must not parse",
            );
        }
    }

    #[test]
    fn test_into_params_carries_wire_fields_and_caller_fields() {
        let wire = leaf_proof_wire();
        let (f, _) = parse_leaf_proof_fields(&wire, 0).unwrap();
        let p = f.into_params(1_000_000, 255);
        assert_eq!(p.amount, 1_000_000, "caller-owned");
        assert_eq!(p.spl_bump, 255, "caller-owned");
        assert_eq!(p.leaf_amount, 3_943_000_000, "from the wire");
        assert_eq!(p.version, 1, "from the wire");
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
