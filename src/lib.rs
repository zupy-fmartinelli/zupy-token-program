use pinocchio::{entrypoint, AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

pub mod constants;
pub mod error;
pub mod helpers;
pub mod instructions;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "ZUPY Token Program",
    project_url: "https://zupy.com",
    contacts: "email:security@zupy.com",
    policy: "https://github.com/zupy-fmartinelli/zupy-token-program/blob/main/SECURITY.md",
    preferred_languages: "en,pt",
    source_code: "https://github.com/zupy-fmartinelli/zupy-token-program",
    auditors: "N/A",
    expiry: "2027-02-28",
    logo: "https://cdn.zupy.com/static/images/token/zupy-coin-purple-512.png"
}

entrypoint!(process_instruction);

/// `burn_tokens` (#11), removed in story 3.40. Reserved: never reuse.
pub const RESERVED_BURN_TOKENS: [u8; 8] = [76, 15, 51, 254, 229, 215, 121, 66];
/// `burn_from_company_pda` (#12), removed in story 3.40. Reserved: never reuse.
pub const RESERVED_BURN_FROM_COMPANY_PDA: [u8; 8] = [43, 207, 204, 77, 74, 93, 165, 34];

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (disc_bytes, data) = instruction_data.split_at(8);
    let disc: [u8; 8] = disc_bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match disc {
        // 1. initialize_token
        [38, 209, 150, 50, 190, 117, 16, 54] => {
            instructions::initialize_token::process(program_id, accounts, data)
        }
        // 2. initialize_metadata
        [35, 215, 241, 156, 122, 208, 206, 212] => {
            instructions::initialize_metadata::process(program_id, accounts, data)
        }
        // 3. update_metadata_field
        [103, 217, 144, 202, 46, 70, 233, 141] => {
            instructions::update_metadata_field::process(program_id, accounts, data)
        }
        // 4. mint_tokens
        [59, 132, 24, 246, 122, 39, 8, 243] => {
            instructions::mint_tokens::process(program_id, accounts, data)
        }
        // 5. treasury_restock_pool
        [94, 62, 103, 106, 93, 87, 173, 24] => {
            instructions::treasury_restock_pool::process(program_id, accounts, data)
        }
        // 6. transfer_from_pool
        [136, 167, 45, 66, 74, 252, 0, 16] => {
            instructions::transfer_from_pool::process(program_id, accounts, data)
        }
        // 7. return_to_pool
        [36, 85, 39, 183, 30, 172, 176, 72] => {
            instructions::return_to_pool::process(program_id, accounts, data)
        }
        // 8. transfer_company_to_user
        [8, 143, 213, 13, 143, 247, 145, 33] => {
            instructions::transfer_company_to_user::process(program_id, accounts, data)
        }
        // 9. transfer_user_to_company
        [186, 233, 22, 40, 87, 223, 252, 131] => {
            instructions::transfer_user_to_company::process(program_id, accounts, data)
        }
        // 10. execute_split_transfer
        [51, 254, 61, 214, 234, 138, 101, 214] => {
            instructions::execute_split_transfer::process(program_id, accounts, data)
        }
        // 11. burn_tokens / 12. burn_from_company_pda — REMOVED (story 3.40, PO
        // 2026-09-30: Z$ is never burned). The discriminators stay RESERVED and
        // must NEVER be reused: an old client or a replayed payload must fail
        // closed, not hit a different instruction.
        RESERVED_BURN_TOKENS | RESERVED_BURN_FROM_COMPANY_PDA => Err(ProgramError::InvalidInstructionData),
        // 13. initialize_rate_limit
        [36, 132, 34, 217, 150, 48, 192, 165] => {
            instructions::initialize_rate_limit::process(program_id, accounts, data)
        }
        // 14. set_paused
        [91, 60, 125, 192, 176, 225, 166, 218] => {
            instructions::set_paused::process(program_id, accounts, data)
        }
        // 15. create_zupy_card
        [92, 114, 17, 0, 219, 121, 112, 150] => {
            instructions::create_zupy_card::process(program_id, accounts, data)
        }
        // 16. create_coupon_nft
        [5, 106, 153, 76, 114, 157, 63, 236] => {
            instructions::create_coupon_nft::process(program_id, accounts, data)
        }
        // 17. mint_coupon_cnft
        [75, 5, 206, 155, 96, 133, 98, 15] => {
            instructions::mint_coupon_cnft::process(program_id, accounts, data)
        }
        // 18. withdraw_to_external
        [114, 198, 185, 119, 169, 163, 29, 251] => {
            instructions::withdraw_to_external::process(program_id, accounts, data)
        }
        // 19. return_user_to_pool
        [151, 33, 221, 193, 7, 214, 10, 199] => {
            instructions::return_user_to_pool::process(program_id, accounts, data)
        }
        // 20. return_user_to_pool_v1 (V1 CPI passthrough, mainnet)
        [41, 120, 49, 208, 53, 163, 70, 32] => {
            instructions::return_user_to_pool_v1::process(program_id, accounts, data)
        }
        // 21. return_to_pool_v1 (company→pool V1 CPI passthrough, mainnet)
        [170, 95, 61, 209, 55, 75, 105, 211] => {
            instructions::return_to_pool_v1::process(program_id, accounts, data)
        }
        // 22. consolidate_leaves (story 3.40) — N leaves of one owner → one leaf
        [131, 243, 51, 130, 117, 203, 4, 156] => {
            instructions::consolidate_leaves::process(program_id, accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 20 LIVE instructions (names must match Anchor exactly).
    const INSTRUCTION_NAMES: [&str; 20] = [
        "initialize_token",
        "initialize_metadata",
        "update_metadata_field",
        "mint_tokens",
        "treasury_restock_pool",
        "transfer_from_pool",
        "return_to_pool",
        "transfer_company_to_user",
        "transfer_user_to_company",
        "execute_split_transfer",
        "initialize_rate_limit",
        "set_paused",
        "create_zupy_card",
        "create_coupon_nft",
        "mint_coupon_cnft",
        "withdraw_to_external",
        "return_user_to_pool",
        "return_user_to_pool_v1",
        "return_to_pool_v1",
        "consolidate_leaves",
    ];

    /// The 20 live discriminators, in the same order.
    const DISCRIMINATORS: [[u8; 8]; 20] = [
        [38, 209, 150, 50, 190, 117, 16, 54],   // initialize_token
        [35, 215, 241, 156, 122, 208, 206, 212], // initialize_metadata
        [103, 217, 144, 202, 46, 70, 233, 141],  // update_metadata_field
        [59, 132, 24, 246, 122, 39, 8, 243],     // mint_tokens
        [94, 62, 103, 106, 93, 87, 173, 24],     // treasury_restock_pool
        [136, 167, 45, 66, 74, 252, 0, 16],      // transfer_from_pool
        [36, 85, 39, 183, 30, 172, 176, 72],     // return_to_pool
        [8, 143, 213, 13, 143, 247, 145, 33],    // transfer_company_to_user
        [186, 233, 22, 40, 87, 223, 252, 131],   // transfer_user_to_company
        [51, 254, 61, 214, 234, 138, 101, 214],  // execute_split_transfer
        [36, 132, 34, 217, 150, 48, 192, 165],   // initialize_rate_limit
        [91, 60, 125, 192, 176, 225, 166, 218],  // set_paused
        [92, 114, 17, 0, 219, 121, 112, 150],    // create_zupy_card
        [5, 106, 153, 76, 114, 157, 63, 236],    // create_coupon_nft
        [75, 5, 206, 155, 96, 133, 98, 15],      // mint_coupon_cnft
        [114, 198, 185, 119, 169, 163, 29, 251], // withdraw_to_external
        [151, 33, 221, 193, 7, 214, 10, 199],    // return_user_to_pool
        [41, 120, 49, 208, 53, 163, 70, 32],     // return_user_to_pool_v1
        [170, 95, 61, 209, 55, 75, 105, 211],    // return_to_pool_v1
        [131, 243, 51, 130, 117, 203, 4, 156],   // consolidate_leaves
    ];

    /// Removed instructions whose discriminators stay reserved (story 3.40).
    const RESERVED: [(&str, [u8; 8]); 2] = [
        ("burn_tokens", RESERVED_BURN_TOKENS),
        ("burn_from_company_pda", RESERVED_BURN_FROM_COMPANY_PDA),
    ];

    fn sha_disc(name: &str) -> [u8; 8] {
        use sha2::{Digest, Sha256};
        Sha256::digest(format!("global:{}", name).as_bytes())[0..8].try_into().unwrap()
    }

    /// Each discriminator (live and reserved) matches SHA256("global:<name>")[0..8]
    #[test]
    fn test_all_discriminators_match_sha256() {
        for (i, name) in INSTRUCTION_NAMES.iter().enumerate() {
            assert_eq!(DISCRIMINATORS[i], sha_disc(name), "Discriminator mismatch for '{}'", name);
        }
        for (name, disc) in RESERVED {
            assert_eq!(disc, sha_disc(name), "Reserved discriminator mismatch for '{}'", name);
        }
    }

    /// Live and reserved discriminators are all distinct (a reserved one is never reused).
    #[test]
    fn test_all_discriminators_unique() {
        let all: Vec<[u8; 8]> = DISCRIMINATORS.iter().copied().chain(RESERVED.iter().map(|r| r.1)).collect();
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "Duplicate discriminator at {} and {}", i, j);
            }
        }
    }

    /// AC3: Instruction data < 8 bytes returns InvalidInstructionData
    #[test]
    fn test_short_instruction_data_returns_error() {
        let pid = Address::from(constants::PROGRAM_ID);
        let short_data = [0u8; 7];
        let result = process_instruction(&pid, &[], &short_data);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    /// AC3: Empty instruction data returns InvalidInstructionData
    #[test]
    fn test_empty_instruction_data_returns_error() {
        let pid = Address::from(constants::PROGRAM_ID);
        let result = process_instruction(&pid, &[], &[]);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    /// AC3: Unknown discriminator returns InvalidInstructionData
    #[test]
    fn test_unknown_discriminator_returns_error() {
        let pid = Address::from(constants::PROGRAM_ID);
        let unknown = [255u8; 8];
        let result = process_instruction(&pid, &[], &unknown);
        assert_eq!(result.unwrap_err(), ProgramError::InvalidInstructionData);
    }

    /// Every live discriminator dispatches to its handler, which returns
    /// NotEnoughAccountKeys with no accounts (proves routing works).
    #[test]
    fn test_valid_discriminator_dispatches_all_live() {
        let pid = Address::from(constants::PROGRAM_ID);
        for (i, disc) in DISCRIMINATORS.iter().enumerate() {
            let result = process_instruction(&pid, &[], disc);
            assert_eq!(
                result.unwrap_err(),
                ProgramError::NotEnoughAccountKeys,
                "Instruction '{}' should return NotEnoughAccountKeys with no accounts",
                INSTRUCTION_NAMES[i],
            );
        }
    }

    /// Story 3.40: the burn discriminators fail closed (no handler, no burn),
    /// with or without payload.
    #[test]
    fn test_reserved_burn_discriminators_fail_closed() {
        let pid = Address::from(constants::PROGRAM_ID);
        for (name, disc) in RESERVED {
            let mut data = Vec::from(disc);
            assert_eq!(process_instruction(&pid, &[], &data), Err(ProgramError::InvalidInstructionData), "{name}");
            data.extend_from_slice(&[0u8; 64]);
            assert_eq!(process_instruction(&pid, &[], &data), Err(ProgramError::InvalidInstructionData), "{name}");
        }
    }

    /// AC3: Valid discriminator with extra data dispatches to handler.
    /// initialize_token (index 0) is implemented and requires 8 accounts,
    /// so it returns NotEnoughAccountKeys even with extra data.
    #[test]
    fn test_discriminator_with_extra_data_dispatches_to_handler() {
        let pid = Address::from(constants::PROGRAM_ID);
        let mut data = Vec::from(DISCRIMINATORS[0]); // initialize_token
        data.extend_from_slice(&[1, 2, 3, 4]); // extra instruction data
        let result = process_instruction(&pid, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    /// 20 live instructions + 2 reserved (21 before story 3.40, minus 2 burns, plus consolidate_leaves).
    #[test]
    fn test_exactly_20_live_instructions() {
        assert_eq!(INSTRUCTION_NAMES.len(), 20);
        assert_eq!(DISCRIMINATORS.len(), 20);
        assert_eq!(RESERVED.len(), 2);
    }
}
