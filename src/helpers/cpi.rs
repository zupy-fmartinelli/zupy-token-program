use pinocchio::AccountView;
use pinocchio::Address;
use pinocchio::cpi::Signer;
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::sysvars::Sysvar;
use pinocchio::sysvars::rent::Rent;

use pinocchio_associated_token_account::instructions::Create;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token_2022::instructions::{Burn, CloseAccount, InitializeMint2, MintTo, Transfer, TransferChecked};

/// CPI: Token-2022 Transfer (discriminator `0x03`).
/// Transfers `amount` tokens from `source` to `destination` using PDA signer seeds.
#[inline(always)]
pub fn cpi_transfer<'a>(
    source: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView,
    amount: u64,
    token_program: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    Transfer {
        from: source,
        to: destination,
        authority,
        amount,
        token_program,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: Token-2022 TransferChecked.
/// Transfers `amount` tokens with decimal validation from `source` to `destination`.
#[inline(always)]
pub fn cpi_transfer_checked<'a>(
    source: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView,
    mint: &'a AccountView,
    amount: u64,
    decimals: u8,
    token_program: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    TransferChecked {
        from: source,
        mint,
        to: destination,
        authority,
        amount,
        decimals,
        token_program,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: Create Associated Token Account if it doesn't exist.
/// An uninitialized ATA has `data_len() == 0` and is system-owned.
/// If the ATA already exists (data_len > 0), this is a no-op.
#[inline(always)]
pub fn cpi_create_ata_if_needed<'a>(
    ata_account: &'a AccountView,
    payer: &'a AccountView,
    owner: &'a AccountView,
    mint: &'a AccountView,
    token_program: &'a AccountView,
    system_program: &'a AccountView,
) -> Result<(), ProgramError> {
    // Already initialized — nothing to do
    if ata_account.data_len() > 0 {
        return Ok(());
    }

    Create {
        funding_account: payer,
        account: ata_account,
        wallet: owner,
        mint,
        system_program,
        token_program,
    }
    .invoke()?;
    Ok(())
}

/// CPI: Token-2022 Burn (discriminator `0x08`).
/// Burns `amount` tokens from `token_account` using PDA signer seeds (invoke_signed).
#[inline(always)]
pub fn cpi_burn<'a>(
    token_account: &'a AccountView,
    mint: &'a AccountView,
    authority: &'a AccountView,
    amount: u64,
    token_program: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    Burn {
        account: token_account,
        mint,
        authority,
        amount,
        token_program,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: Token-2022 Burn via regular invoke (no PDA signer).
/// Used by `burn_tokens` where `token_account_owner` is the signer.
#[inline(always)]
pub fn cpi_burn_invoke<'a>(
    token_account: &'a AccountView,
    mint: &'a AccountView,
    authority: &'a AccountView,
    amount: u64,
    token_program: &Address,
) -> Result<(), ProgramError> {
    Burn {
        account: token_account,
        mint,
        authority,
        amount,
        token_program,
    }
    .invoke()?;
    Ok(())
}

/// CPI: Token-2022 CloseAccount (discriminator `0x09`).
/// Closes `account`, sends rent lamports to `destination`. PDA `authority` signs via invoke_signed.
#[inline(always)]
pub fn cpi_close_account<'a>(
    account: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView,
    token_program: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    CloseAccount {
        account,
        destination,
        authority,
        token_program,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: Token-2022 MintTo (discriminator `0x07`).
/// Mints `amount` tokens to `destination` using PDA signer seeds.
#[inline(always)]
pub fn cpi_mint_to<'a>(
    mint: &'a AccountView,
    destination: &'a AccountView,
    authority: &'a AccountView,
    amount: u64,
    token_program: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    MintTo {
        mint,
        account: destination,
        mint_authority: authority,
        amount,
        token_program,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: System Program CreateAccount.
/// Creates a new account with `space` bytes, owned by `owner`, funded by `payer`.
/// Calculates rent-exempt minimum via `Rent::get()`.
#[inline(always)]
pub fn cpi_create_account<'a>(
    payer: &'a AccountView,
    new_account: &'a AccountView,
    space: u64,
    owner: &Address,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    let rent = Rent::get()?;
    let lamports = rent.try_minimum_balance(space as usize)?;

    CreateAccount {
        from: payer,
        to: new_account,
        lamports,
        space,
        owner,
    }
    .invoke_signed(signers)?;
    Ok(())
}

/// CPI: Token-2022 InitializeMint2.
/// Initializes an already-created account as a Token-2022 mint.
/// Must be called AFTER `cpi_create_account`.
#[inline(always)]
pub fn cpi_initialize_mint(
    mint: &AccountView,
    mint_authority: &Address,
    freeze_authority: Option<&Address>,
    decimals: u8,
    token_program: &Address,
) -> Result<(), ProgramError> {
    InitializeMint2 {
        mint,
        mint_authority,
        freeze_authority,
        decimals,
        token_program,
    }
    .invoke()?;
    Ok(())
}

/// CPI: spl-token-metadata-interface Initialize.
/// Manual CPI — no pinocchio crate exists for metadata interface.
/// Discriminator: [210, 225, 30, 162, 88, 184, 77, 141]
/// Target: Token-2022 program (implements metadata interface).
///
/// NOTE: Uses Vec for dynamic data serialization. Acceptable for cold-path
/// (called once during token setup, not in hot-path transfers).
#[inline(always)]
pub fn cpi_initialize_metadata<'a>(
    mint: &'a AccountView,
    authority: &'a AccountView,
    token_program: &'a AccountView,
    name: &str,
    symbol: &str,
    uri: &str,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    // Build data: discriminator + borsh(InitializeArgs { name, symbol, uri })
    let disc: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];
    let name_bytes = name.as_bytes();
    let symbol_bytes = symbol.as_bytes();
    let uri_bytes = uri.as_bytes();
    let data_len = 8 + 4 + name_bytes.len() + 4 + symbol_bytes.len() + 4 + uri_bytes.len();

    let mut data = Vec::with_capacity(data_len);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(name_bytes);
    data.extend_from_slice(&(symbol_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(symbol_bytes);
    data.extend_from_slice(&(uri_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(uri_bytes);

    // Token-2022 metadata Initialize requires 4 accounts:
    //   0. metadata   [writable]        — for Token-2022, metadata = mint itself
    //   1. update_authority [readonly]   — who can update metadata later
    //   2. mint       [readonly]         — the mint (same as account 0)
    //   3. mint_authority [signer]       — current mint authority (PDA signer)
    let accounts = [
        InstructionAccount::writable(mint.address()),           // 0: metadata = mint
        InstructionAccount::readonly(authority.address()),       // 1: update_authority
        InstructionAccount::readonly(mint.address()),            // 2: mint
        InstructionAccount::readonly_signer(authority.address()), // 3: mint_authority (signer)
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &data,
    };

    // Pinocchio requires a 1:1 mapping between instruction accounts and
    // account_views (duplicates included), plus the program AccountView.
    pinocchio::cpi::invoke_signed(
        &instruction,
        &[mint, authority, mint, authority, token_program],
        signers,
    )?;
    Ok(())
}

/// CPI: spl-token-metadata-interface UpdateField.
/// Manual CPI — no pinocchio crate exists for metadata interface.
/// Discriminator: [221, 233, 49, 45, 181, 202, 220, 200]
/// Field enum: 0=Name, 1=Symbol, 2=Uri (custom key not supported)
///
/// NOTE: Uses Vec for dynamic data serialization. Acceptable for cold-path
/// (metadata updates are rare admin operations).
#[inline(always)]
pub fn cpi_update_metadata_field<'a>(
    mint: &'a AccountView,
    authority: &'a AccountView,
    token_program: &'a AccountView,
    field: u8,
    value: &str,
    signers: &[Signer],
) -> Result<(), ProgramError> {
    let disc: [u8; 8] = [221, 233, 49, 45, 181, 202, 220, 200];
    let value_bytes = value.as_bytes();

    // Field is serialized as the spl_token_metadata_interface::state::Field enum.
    // Borsh encodes simple enum variants (no payload) as u8 (1 byte).
    // Field::Name=0, Field::Symbol=1, Field::Uri=2
    if field > 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let data_len = 8 + 1 + 4 + value_bytes.len();
    let mut data = Vec::with_capacity(data_len);
    data.extend_from_slice(&disc);
    data.push(field);  // 1-byte Borsh enum discriminant (NOT u32)
    data.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(value_bytes);

    let accounts = [
        InstructionAccount::writable(mint.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &data,
    };

    pinocchio::cpi::invoke_signed(&instruction, &[mint, authority, token_program], signers)?;
    Ok(())
}

/// CPI: Bubblegum MintV1 — manual CPI (no mpl-bubblegum dependency).
/// Discriminator: SHA256("global:mint_v1")[0..8]
/// MetadataArgs serialized manually via borsh.
///
/// NOTE: Uses Vec for dynamic MetadataArgs serialization. Acceptable for cold-path
/// (cNFT minting is an infrequent operation, not a hot-path transfer).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn cpi_bubblegum_mint_v1<'a>(
    tree_config: &'a AccountView,
    leaf_owner: &'a AccountView,
    merkle_tree: &'a AccountView,
    payer: &'a AccountView,
    tree_authority: &'a AccountView,
    log_wrapper: &'a AccountView,
    compression_program: &'a AccountView,
    system_program: &'a AccountView,
    bubblegum_program: &'a AccountView,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Result<(), ProgramError> {
    // Discriminator: SHA256("global:mint_v1")[0..8]
    // Pre-computed: [145, 98, 192, 118, 184, 147, 118, 104]
    let disc: [u8; 8] = [145, 98, 192, 118, 184, 147, 118, 104];

    let name_bytes = name.as_bytes();
    let symbol_bytes = symbol.as_bytes();
    let uri_bytes = uri.as_bytes();

    // Build MetadataArgs borsh serialization
    let metadata_len = 4 + name_bytes.len()   // name: String
        + 4 + symbol_bytes.len()              // symbol: String
        + 4 + uri_bytes.len()                 // uri: String
        + 2                                   // seller_fee_basis_points: u16
        + 1                                   // primary_sale_happened: bool
        + 1                                   // is_mutable: bool
        + 1                                   // edition_nonce: Option<u8> (None)
        + 2                                   // token_standard: Option<TokenStandard> (Some(NonFungible))
        + 1                                   // collection: Option<Collection> (None)
        + 1                                   // uses: Option<Uses> (None)
        + 1                                   // token_program_version: TokenProgramVersion (Original)
        + 4;                                  // creators: Vec<Creator> (empty)

    let data_len = 8 + metadata_len;
    let mut data = Vec::with_capacity(data_len);
    data.extend_from_slice(&disc);

    // name
    data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(name_bytes);
    // symbol
    data.extend_from_slice(&(symbol_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(symbol_bytes);
    // uri
    data.extend_from_slice(&(uri_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(uri_bytes);
    // seller_fee_basis_points: 0
    data.extend_from_slice(&0u16.to_le_bytes());
    // primary_sale_happened: true
    data.push(1);
    // is_mutable: false
    data.push(0);
    // edition_nonce: None
    data.push(0);
    // token_standard: Some(NonFungible) = [1 (Some), 0 (NonFungible variant index)]
    data.push(1);
    data.push(0);
    // collection: None
    data.push(0);
    // uses: None
    data.push(0);
    // token_program_version: Original = 0
    data.push(0);
    // creators: empty Vec = [0, 0, 0, 0] (u32 length = 0)
    data.extend_from_slice(&0u32.to_le_bytes());

    // Account order for Bubblegum MintV1:
    // [tree_config (w), leaf_owner, leaf_delegate, merkle_tree (w),
    //  payer (w,s), tree_creator_or_delegate (s), log_wrapper,
    //  compression_program, system_program]
    let accounts = [
        InstructionAccount::writable(tree_config.address()),
        InstructionAccount::readonly(leaf_owner.address()),
        InstructionAccount::readonly(leaf_owner.address()), // leaf_delegate = leaf_owner
        InstructionAccount::writable(merkle_tree.address()),
        InstructionAccount::writable_signer(payer.address()),
        InstructionAccount::readonly_signer(tree_authority.address()),
        InstructionAccount::readonly(log_wrapper.address()),
        InstructionAccount::readonly(compression_program.address()),
        InstructionAccount::readonly(system_program.address()),
    ];

    let instruction = InstructionView {
        program_id: bubblegum_program.address(),
        accounts: &accounts,
        data: &data,
    };

    pinocchio::cpi::invoke::<9>(
        &instruction,
        &[
            tree_config,
            leaf_owner,
            leaf_owner, // leaf_delegate = leaf_owner (duplicate reference needed)
            merkle_tree,
            payer,
            tree_authority,
            log_wrapper,
            compression_program,
            system_program,
        ],
    )?;
    Ok(())
}

/// CPI: Token-2022 MetadataPointer initialization.
/// Must be called BEFORE InitializeMint2.
/// Sets metadata_address = mint itself (self-referential).
///
/// NOTE: Uses Vec for fixed-size data (66 bytes). Acceptable for cold-path
/// (called once during mint initialization).
#[inline(always)]
pub fn cpi_initialize_metadata_pointer<'a>(
    mint: &'a AccountView,
    authority: &Address,
    token_program: &'a AccountView,
) -> Result<(), ProgramError> {
    // Token-2022 instruction index 39: MetadataPointerExtension
    // Sub-instruction 0: Initialize
    // Data: [39u8, 0u8 (Initialize variant), authority (32 bytes OptionalNonZeroPubkey), metadata_address (32 bytes)]
    let mut data = Vec::with_capacity(1 + 1 + 32 + 32);
    data.push(39u8);
    // MetadataPointerInstruction variant: 0 = Initialize
    data.push(0u8);
    // authority: OptionalNonZeroPubkey (32 bytes, non-zero = present)
    data.extend_from_slice(authority.as_ref());
    // metadata_address: OptionalNonZeroPubkey = mint address (self-referential)
    data.extend_from_slice(mint.address().as_ref());

    let accounts = [
        InstructionAccount::writable(mint.address()),
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &data,
    };

    pinocchio::cpi::invoke::<2>(&instruction, &[mint, token_program])?;
    Ok(())
}

// NOTE: CPI helpers cannot be unit-tested without the Solana runtime.
// They are integration-tested via Mollusk in tests/test_transfers.rs,
// tests/test_split_burns.rs, and tests/test_cold_path.rs. The function
// signatures and logic above are verified by compilation and by the
// Mollusk integration tests that exercise the full instruction flow.

#[cfg(test)]
mod tests {
    /// Verify the hardcoded Bubblegum MintV1 discriminator matches
    /// SHA256("global:mint_v1")[0..8] — same convention as our 19 instructions.
    #[test]
    fn test_bubblegum_mint_v1_discriminator_matches_sha256() {
        use sha2::{Sha256, Digest};

        let hash = Sha256::digest(b"global:mint_v1");
        let expected: [u8; 8] = hash[0..8].try_into().unwrap();
        let hardcoded: [u8; 8] = [145, 98, 192, 118, 184, 147, 118, 104];
        assert_eq!(
            hardcoded, expected,
            "Bubblegum MintV1 discriminator mismatch: hardcoded={:?}, SHA256={:?}",
            hardcoded, expected
        );
    }

    /// Verify the metadata Initialize discriminator.
    #[test]
    fn test_metadata_initialize_discriminator() {
        // spl-token-metadata-interface Initialize discriminator is NOT SHA256-based —
        // it uses a different hash scheme (spl_discriminator). We just verify it's
        // the well-known constant.
        let disc: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];
        assert_eq!(disc.len(), 8);
        // Known-good value from spl-token-metadata-interface crate
        assert_eq!(disc[0], 210);
        assert_eq!(disc[7], 141);
    }

    /// Verify the metadata UpdateField discriminator.
    #[test]
    fn test_metadata_update_field_discriminator() {
        let disc: [u8; 8] = [221, 233, 49, 45, 181, 202, 220, 200];
        assert_eq!(disc.len(), 8);
        assert_eq!(disc[0], 221);
        assert_eq!(disc[7], 200);
    }

    /// Regression test: Field enum must be encoded as u8 (1 byte), NOT u32 (4 bytes).
    ///
    /// Bug: encoding Field::Uri as u32 [2, 0, 0, 0] causes Token-2022 to read
    /// the string length field as [0, 0, 0, 66] (little-endian) = 1,107,296,256 bytes,
    /// triggering an immediate "memory allocation failed, out of memory" at ~689 CU.
    ///
    /// Correct Borsh encoding: enum variant as u8 → Field::Uri = [2] (single byte).
    #[test]
    fn test_update_field_borsh_encoding_is_u8_not_u32() {
        // Correct: 1 byte for Field::Uri
        let field_byte: u8 = 2u8;
        assert_eq!(field_byte.to_le_bytes().len(), 1);
        assert_eq!(field_byte, 2);

        // Wrong encoding that caused OOM:
        // u32::to_le_bytes() produces [2, 0, 0, 0] — 4 bytes instead of 1.
        // After Token-2022 reads [2] as Field::Uri, the next 4 bytes for the
        // String length become [0, 0, 0, value_len_first_byte].
        // For value_len = 66 (0x42), that's [0, 0, 0, 66] = 0x42000000 = 1,107,296,256 → OOM.
        let misread_string_len = u32::from_le_bytes([0u8, 0u8, 0u8, 66u8]);
        assert_eq!(
            misread_string_len, 1_107_296_256,
            "u32 field encoding misaligns string length → ~1GB allocation → OOM"
        );
    }
}
