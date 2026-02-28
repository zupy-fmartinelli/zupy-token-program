use five8_const::decode_32_const;
use light_sdk_pinocchio::cpi::{derive_light_cpi_signer, CpiSigner};

// ── Token State Seed ─────────────────────────────────────────────────
pub const TOKEN_STATE_SEED: &[u8] = b"token_state";

// ── Token Metadata (unified: ZUPY for all environments) ─────────────
pub const TOKEN_NAME: &str = "ZUPY";
pub const TOKEN_SYMBOL: &str = "ZUPY";
pub const TOKEN_DECIMALS: u8 = 6;

// ── Metadata URI (feature-flagged: different IPFS hashes) ────────────
#[cfg(not(feature = "production"))]
pub const METADATA_URI: &str = "ipfs://bafkreig7ifwir2wy52csyhmoa3x6yfsqkhs2pfqnoc4g3gavq2ep5hmfpu";
#[cfg(feature = "production")]
pub const METADATA_URI: &str = "ipfs://bafkreifk4n4oqeiz3jj2dhazypt6qhtpnbinh6ksfxs6eyfwzxu6sroe64";

// ── Genesis Supply (raw u64 with 6 decimals) ─────────────────────────
pub const GENESIS_SUPPLY: u64 = 5_000_000_000_000; // 5M ZUPY

// ── Rate Limits ──────────────────────────────────────────────────────
// Rate limits remain feature-flagged: devnet relaxed for testing/migration
#[cfg(not(feature = "production"))]
pub const DAILY_MINT_LIMIT: u64 = 100_000_000_000_000; // 100M
#[cfg(feature = "production")]
pub const DAILY_MINT_LIMIT: u64 = 1_000_000_000_000; // 1M

#[cfg(not(feature = "production"))]
pub const PER_TX_MINT_LIMIT: u64 = 10_000_000_000_000; // 10M
#[cfg(feature = "production")]
pub const PER_TX_MINT_LIMIT: u64 = 50_000_000_000; // 50K

pub const PER_TX_AUTO_LIMIT: u64 = 100_000_000_000; // 100K (both envs)
pub const DAILY_AUTO_LIMIT: u64 = 500_000_000_000; // 500K (both envs)

// ── Program ID (unified: same keypair for devnet + mainnet) ──────────
pub const PROGRAM_ID: [u8; 32] = decode_32_const("ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU");

// ── External Program IDs (compile-time constants) ────────────────────
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] =
    decode_32_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM_ID: [u8; 32] =
    decode_32_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM_ID: [u8; 32] =
    decode_32_const("11111111111111111111111111111111");
pub const BUBBLEGUM_PROGRAM_ID: [u8; 32] =
    decode_32_const("BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY");
pub const SPL_ACCOUNT_COMPRESSION_ID: [u8; 32] =
    decode_32_const("cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK");
pub const SPL_NOOP_ID: [u8; 32] =
    decode_32_const("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV");

// ── Light Protocol Program IDs (ZK Compressed Tokens) ────────────────
/// Light compressed-token program (cToken). CPI target for all compressed
/// token operations: compress, decompress, transfer, burn.
pub const LIGHT_COMPRESSED_TOKEN_PROGRAM_ID: [u8; 32] =
    decode_32_const("cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m");
/// Light System program — manages compressed account state trees.
pub const LIGHT_SYSTEM_PROGRAM_ID: [u8; 32] =
    decode_32_const("SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7");
/// Account Compression program — manages Merkle trees and nullifier queues.
pub const ACCOUNT_COMPRESSION_PROGRAM_ID: [u8; 32] =
    decode_32_const("compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq");
/// Light Registry program — tracks registered programs in the Light ecosystem.
pub const LIGHT_REGISTRY_PROGRAM_ID: [u8; 32] =
    decode_32_const("Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX");

/// CPI authority PDA for the Light Token (cToken) program.
/// = find_program_address(&[b"cpi_authority"], LIGHT_COMPRESSED_TOKEN_PROGRAM_ID)
/// Hardcoded from light-token-pinocchio-0.22.0 constants — verified matches derive_ctoken_authority().
/// Passed as accounts[2] in compress_spl_token_account CPI.
pub const LIGHT_TOKEN_CPI_AUTHORITY: [u8; 32] =
    decode_32_const("GXtd2izAiMJPwMEjfgTRH3d7k9mjn4Jq3JrWFv9gySYy");
/// Registered Program PDA for the Light system.
/// Constant from light-compressed-account crate (REGISTERED_PROGRAM_PDA).
/// Passed as accounts[4] in compress_spl_token_account CPI.
pub const REGISTERED_PROGRAM_PDA: [u8; 32] =
    decode_32_const("35hkDgaAKwMCaxRz2ocSZ6NaUrtKkyNqU6c4RV3tYJRh");
/// Account Compression Authority PDA.
/// = find_program_address(&[b"cpi_authority"], LIGHT_SYSTEM_PROGRAM_ID)
/// Constant from light-compressed-account crate (ACCOUNT_COMPRESSION_AUTHORITY_PDA).
/// Passed as accounts[6] in compress_spl_token_account CPI.
pub const ACCOUNT_COMPRESSION_AUTHORITY: [u8; 32] =
    decode_32_const("HwXnGK3tPkkVY6P439H2p68AxpeuWXd5PcrAxFpbmfbA");

/// Compile-time CPI signer for the Light System Program.
///
/// Derived from ZUPY program ID: `ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU`.
/// Required for Path B operations (compressed → compressed).
/// Path A (compress from SPL) uses a different CPI mechanism — see `compressed_accounts.rs`.
///
/// `derive_light_cpi_signer!` is a **compile-time proc-macro** from `light-sdk-pinocchio`.
/// It computes `find_program_address(&[b"cpi_authority"], program_id)` at compile time
/// and stores the result in a `CpiSigner { program_id, cpi_signer, bump }` struct.
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU");

// ── PDA Seed Constants ───────────────────────────────────────────────
pub const ZUPY_CARD_SEED: &[u8] = b"zupy_card";
pub const ZUPY_CARD_MINT_SEED: &[u8] = b"zupy_card_mint";
pub const LOYALTY_CARD_SEED: &[u8] = b"loyalty_card";
pub const COUPON_SEED: &[u8] = b"coupon";
pub const CAMPAIGN_SEED: &[u8] = b"campaign";
pub const RATE_LIMIT_SEED: &[u8] = b"rate_limit";
pub const COMPANY_SEED: &[u8] = b"company";
pub const USER_SEED: &[u8] = b"user";
pub const USER_PDA_SEED: &[u8] = b"user_pda";
pub const INCENTIVE_POOL_SEED: &[u8] = b"incentive_pool";
pub const DISTRIBUTION_POOL_SEED: &[u8] = b"distribution_pool";

// ── Three-Wallet Security Pubkeys ────────────────────────────────────
// Treasury: Trezor hardware wallet (unified for all environments)
pub const TREASURY_WALLET_PUBKEY: [u8; 32] =
    decode_32_const("AZjCtbrNGsSztGyWcqKdyq4sP2FnH3ZQCMyCErUzwZH9");

// Mint & Transfer authorities: Vault Transit (unified for all environments)
pub const MINT_AUTHORITY_PUBKEY: [u8; 32] =
    decode_32_const("ZUPYn23hsz3U5ARv9jcM8AcG46mC2puoJiVQ8TGxGHQ");
pub const TRANSFER_AUTHORITY_PUBKEY: [u8; 32] =
    decode_32_const("ZUPYtXrbnstMAZP5c4V6kzok9eTrGyGBbwpPdte1QSd");

// ── Memo Constants ───────────────────────────────────────────────────
pub const MEMO_PREFIX: &str = "zupy";
pub const MEMO_VERSION: &str = "v1";

// ── Seconds per day (for rate limit reset) ───────────────────────────
pub const SECONDS_PER_DAY: i64 = 86_400;

// ── Token-2022 Mint Account Size ───────────────────────────────────
/// Standard Token-2022 mint account size (no extensions): 82 bytes.
pub const BASIC_MINT_SIZE: u64 = 82;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_state_seed() {
        assert_eq!(TOKEN_STATE_SEED, b"token_state");
    }

    #[test]
    fn test_token_metadata() {
        assert_eq!(TOKEN_NAME, "ZUPY");
        assert_eq!(TOKEN_SYMBOL, "ZUPY");
        assert_eq!(TOKEN_DECIMALS, 6);
    }

    #[test]
    fn test_genesis_supply() {
        assert_eq!(GENESIS_SUPPLY, 5_000_000_000_000);
    }

    #[test]
    fn test_rate_limits_devnet() {
        // Default feature is devnet — relaxed limits for testing
        assert_eq!(DAILY_MINT_LIMIT, 100_000_000_000_000);
        assert_eq!(PER_TX_MINT_LIMIT, 10_000_000_000_000);
        assert_eq!(PER_TX_AUTO_LIMIT, 100_000_000_000);
        assert_eq!(DAILY_AUTO_LIMIT, 500_000_000_000);
    }

    #[test]
    fn test_external_program_ids_are_32_bytes() {
        assert_eq!(TOKEN_2022_PROGRAM_ID.len(), 32);
        assert_eq!(ATA_PROGRAM_ID.len(), 32);
        assert_eq!(SYSTEM_PROGRAM_ID.len(), 32);
        assert_eq!(BUBBLEGUM_PROGRAM_ID.len(), 32);
        assert_eq!(SPL_ACCOUNT_COMPRESSION_ID.len(), 32);
        assert_eq!(SPL_NOOP_ID.len(), 32);
    }

    #[test]
    fn test_light_protocol_program_ids_are_32_bytes_and_nonzero() {
        assert_eq!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.len(), 32);
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, [0u8; 32]);

        assert_eq!(LIGHT_SYSTEM_PROGRAM_ID.len(), 32);
        assert_ne!(LIGHT_SYSTEM_PROGRAM_ID, [0u8; 32]);

        assert_eq!(ACCOUNT_COMPRESSION_PROGRAM_ID.len(), 32);
        assert_ne!(ACCOUNT_COMPRESSION_PROGRAM_ID, [0u8; 32]);

        assert_eq!(LIGHT_REGISTRY_PROGRAM_ID.len(), 32);
        assert_ne!(LIGHT_REGISTRY_PROGRAM_ID, [0u8; 32]);
    }

    #[test]
    fn test_light_compressed_token_program_id_matches_known_address() {
        // cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m — canonical Light cToken program
        // Verify first and last bytes as a sanity check (full check via decode_32_const)
        assert_eq!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID[0], 0x09); // 'c' base58-decoded first byte area
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID[31], 0x00);
    }

    #[test]
    fn test_light_cpi_signer_program_id_matches_our_program() {
        assert_eq!(LIGHT_CPI_SIGNER.program_id, PROGRAM_ID,
            "LIGHT_CPI_SIGNER.program_id must be our program ID");
        // CPI signer pubkey is non-zero (derived from program ID + "cpi_authority" seed)
        assert_ne!(LIGHT_CPI_SIGNER.cpi_signer, [0u8; 32]);
        // Bump must be a valid canonical PDA bump (1-255)
        assert!(LIGHT_CPI_SIGNER.bump >= 1 && LIGHT_CPI_SIGNER.bump <= 255);
    }

    #[test]
    fn test_light_protocol_program_ids_are_all_distinct() {
        // All Light program IDs must be different from each other and from existing program IDs
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, LIGHT_SYSTEM_PROGRAM_ID);
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, ACCOUNT_COMPRESSION_PROGRAM_ID);
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, LIGHT_REGISTRY_PROGRAM_ID);
        assert_ne!(LIGHT_SYSTEM_PROGRAM_ID, ACCOUNT_COMPRESSION_PROGRAM_ID);
        assert_ne!(LIGHT_SYSTEM_PROGRAM_ID, LIGHT_REGISTRY_PROGRAM_ID);
        assert_ne!(ACCOUNT_COMPRESSION_PROGRAM_ID, LIGHT_REGISTRY_PROGRAM_ID);
        // None should collide with Token-2022 or system program
        assert_ne!(LIGHT_COMPRESSED_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID);
        assert_ne!(LIGHT_SYSTEM_PROGRAM_ID, SYSTEM_PROGRAM_ID);
    }

    #[test]
    fn test_system_program_is_all_zeros() {
        assert_eq!(SYSTEM_PROGRAM_ID, [0u8; 32]);
    }

    #[test]
    fn test_pda_seeds_not_empty() {
        assert!(!ZUPY_CARD_SEED.is_empty());
        assert!(!RATE_LIMIT_SEED.is_empty());
        assert!(!COMPANY_SEED.is_empty());
        assert!(!USER_SEED.is_empty());
        assert!(!INCENTIVE_POOL_SEED.is_empty());
        assert!(!DISTRIBUTION_POOL_SEED.is_empty());
        assert!(!COUPON_SEED.is_empty());
    }

    #[test]
    fn test_light_cpi_pdas_are_32_bytes_and_nonzero() {
        assert_eq!(LIGHT_TOKEN_CPI_AUTHORITY.len(), 32);
        assert_ne!(LIGHT_TOKEN_CPI_AUTHORITY, [0u8; 32]);

        assert_eq!(REGISTERED_PROGRAM_PDA.len(), 32);
        assert_ne!(REGISTERED_PROGRAM_PDA, [0u8; 32]);

        assert_eq!(ACCOUNT_COMPRESSION_AUTHORITY.len(), 32);
        assert_ne!(ACCOUNT_COMPRESSION_AUTHORITY, [0u8; 32]);
    }

    #[test]
    fn test_light_cpi_pdas_are_all_distinct() {
        assert_ne!(LIGHT_TOKEN_CPI_AUTHORITY, REGISTERED_PROGRAM_PDA);
        assert_ne!(LIGHT_TOKEN_CPI_AUTHORITY, ACCOUNT_COMPRESSION_AUTHORITY);
        assert_ne!(REGISTERED_PROGRAM_PDA, ACCOUNT_COMPRESSION_AUTHORITY);
        // None should collide with program IDs
        assert_ne!(LIGHT_TOKEN_CPI_AUTHORITY, LIGHT_COMPRESSED_TOKEN_PROGRAM_ID);
        assert_ne!(REGISTERED_PROGRAM_PDA, LIGHT_SYSTEM_PROGRAM_ID);
        assert_ne!(ACCOUNT_COMPRESSION_AUTHORITY, ACCOUNT_COMPRESSION_PROGRAM_ID);
    }

    #[test]
    fn test_three_wallet_pubkeys_are_32_bytes() {
        assert_eq!(TREASURY_WALLET_PUBKEY.len(), 32);
        assert_eq!(MINT_AUTHORITY_PUBKEY.len(), 32);
        assert_eq!(TRANSFER_AUTHORITY_PUBKEY.len(), 32);
    }

    #[test]
    fn test_program_id() {
        assert_eq!(PROGRAM_ID.len(), 32);
        assert_ne!(PROGRAM_ID, [0u8; 32]);
    }

    #[test]
    fn test_memo_constants() {
        assert_eq!(MEMO_PREFIX, "zupy");
        assert_eq!(MEMO_VERSION, "v1");
    }

    #[test]
    fn test_basic_mint_size() {
        assert_eq!(BASIC_MINT_SIZE, 82);
    }
}
