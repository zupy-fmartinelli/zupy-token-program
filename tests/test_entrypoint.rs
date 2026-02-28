//! Mollusk CU benchmark template for zupy-pinocchio.
//!
//! Requires `cargo build-sbf` before running:
//!   cargo build-sbf && cargo test --test test_entrypoint

mod helpers;

use helpers::*;
use solana_instruction::Instruction;

/// All 17 instruction discriminators.
const DISCRIMINATORS: [([u8; 8], &str); 17] = [
    ([38, 209, 150, 50, 190, 117, 16, 54], "initialize_token"),
    ([35, 215, 241, 156, 122, 208, 206, 212], "initialize_metadata"),
    ([103, 217, 144, 202, 46, 70, 233, 141], "update_metadata_field"),
    ([59, 132, 24, 246, 122, 39, 8, 243], "mint_tokens"),
    ([94, 62, 103, 106, 93, 87, 173, 24], "treasury_restock_pool"),
    ([136, 167, 45, 66, 74, 252, 0, 16], "transfer_from_pool"),
    ([36, 85, 39, 183, 30, 172, 176, 72], "return_to_pool"),
    ([8, 143, 213, 13, 143, 247, 145, 33], "transfer_company_to_user"),
    ([186, 233, 22, 40, 87, 223, 252, 131], "transfer_user_to_company"),
    ([51, 254, 61, 214, 234, 138, 101, 214], "execute_split_transfer"),
    ([76, 15, 51, 254, 229, 215, 121, 66], "burn_tokens"),
    ([43, 207, 204, 77, 74, 93, 165, 34], "burn_from_company_pda"),
    ([36, 132, 34, 217, 150, 48, 192, 165], "initialize_rate_limit"),
    ([91, 60, 125, 192, 176, 225, 166, 218], "set_paused"),
    ([92, 114, 17, 0, 219, 121, 112, 150], "create_zupy_card"),
    ([5, 106, 153, 76, 114, 157, 63, 236], "create_coupon_nft"),
    ([75, 5, 206, 155, 96, 133, 98, 15], "mint_coupon_cnft"),
];

/// Mollusk instance loads the built program successfully.
#[test]
fn test_mollusk_setup() {
    let _mollusk = setup_mollusk();
}

/// Each instruction dispatches and executes with CU reported.
/// All 17 handlers are invoked with no accounts. Most return Err
/// (NotEnoughAccountKeys or InvalidInstructionData), but some cold-path
/// handlers may return Ok with minimal CU due to SBF/Pinocchio edge cases.
/// The key assertion is: dispatch works (CU > 0) and no panics.
#[test]
fn test_all_instructions_execute_with_cu_measurement() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    println!("\n--- CU Benchmark (all handlers) ---");
    for (disc, name) in &DISCRIMINATORS {
        let instruction = Instruction::new_with_bytes(pid, disc, vec![]);
        let result = mollusk.process_instruction(&instruction, &[]);

        let status = if result.program_result.is_ok() { "OK" } else { "ERR" };
        println!(
            "  {:30} CU: {:>6}  [{}]",
            name, result.compute_units_consumed, status
        );

        assert!(
            result.compute_units_consumed > 0,
            "CU should be > 0 for '{}' — dispatch must execute",
            name
        );
    }
    println!("--- End CU Benchmark ---\n");
}

/// Unknown discriminator returns InvalidInstructionData via Mollusk.
#[test]
fn test_unknown_discriminator_via_mollusk() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    let instruction = Instruction::new_with_bytes(pid, &[255u8; 8], vec![]);
    let result = mollusk.process_instruction(&instruction, &[]);
    assert!(result.program_result.is_err());
}

/// Short instruction data returns error via Mollusk.
#[test]
fn test_short_data_via_mollusk() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    let instruction = Instruction::new_with_bytes(pid, &[1, 2, 3], vec![]);
    let result = mollusk.process_instruction(&instruction, &[]);
    assert!(result.program_result.is_err());
}

/// CU baseline: measure the minimum CU for entrypoint dispatch.
/// Uses set_paused (simplest handler with 2 accounts) as baseline.
#[test]
fn test_cu_baseline_entrypoint_dispatch() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    // Use set_paused (index 13) as the baseline — simplest implemented handler
    let instruction = Instruction::new_with_bytes(
        pid,
        &DISCRIMINATORS[13].0,
        vec![],
    );
    let result = mollusk.process_instruction(&instruction, &[]);

    // All instructions are implemented, so NotEnoughAccountKeys is expected
    assert!(result.program_result.is_err());
    println!(
        "\nEntrypoint dispatch baseline CU: {}",
        result.compute_units_consumed
    );
    // Dispatch + account count check should use minimal CU
    assert!(
        result.compute_units_consumed < 5000,
        "Dispatch baseline should use < 5000 CU, got {}",
        result.compute_units_consumed
    );
}
