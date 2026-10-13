use pinocchio::cpi::{Seed, Signer};
use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;

use crate::constants::{COMPANY_SEED, USER_SEED};
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::TRANSFER_V1_DISC;
use crate::helpers::instruction_data::{parse_string, parse_u64, parse_u8};
use crate::helpers::memo::validate_memo_format;
use crate::helpers::pda::{validate_id_pda, validate_light_ctoken_program};
use crate::helpers::transfer_validation::validate_transfer_common_compressed;
use crate::helpers::v1_transfer::{
    invoke_v1_transfer_signed, v1_first_output, validate_v1_authority, validate_v1_transfer_payload, V1Leg,
};

/// Validation accounts every layout starts with (`[0..5]`).
const C2U_BASE_ACCOUNTS: usize = 5;
/// LEGACY layout: the V1 cToken CPI tail starts right after the base accounts.
pub const C2U_LEGACY_V1_CPI_ACCOUNTS_START: usize = C2U_BASE_ACCOUNTS;
/// NEW layout (story 3.40): `[5] fee_payer, [6] system, [7] cToken`, CPI tail from `[8]`
/// — byte-for-byte the account layout of `transfer_user_to_company`.
pub const C2U_V1_CPI_ACCOUNTS_START: usize = 8;
/// LEGACY layout: the V1 TRANSFER starts at this data offset.
const C2U_LEGACY_V1_OFFSET: usize = 18;

/// Process `transfer_company_to_user` (store → customer reward), V1 CPI passthrough.
///
/// **MEASURED 2026-09-29 (story 3.21): WORKS on mainnet** — public tx
/// `66bFvExdZpcnXirEXS1br2JoxL56Qk1yE7CAuDWvGabZmPSs9tcussJyRvZpvPRS4t7B7wKfqTNUPdak1mBHxYu8`
/// (slot 451624459); a 1-in-8 sample of 1,000 signatures had 68 successes and 5 errors.
/// The mainnet cToken dispatches the Anchor `global:transfer` (V1) instruction
/// (an `lddw` immediate in the binary). disc=3 (the former `cpi_compressed_transfer`, removed in 36.5) does
/// NOT work for compressed Z$ (`Custom(18063)`, story 3.17).
///
/// ## 2026-09-30 (story 3.40) — hardened, two layouts
///
/// Up to `da2b261` this instruction checked only the V1 discriminator and the two
/// PDAs, then signed ANY payload with the company PDA (review of 3.21, deferred:
/// a compromised backend had no on-chain brake here). It now runs the same
/// payload validation as the client-spend instructions
/// ([`validate_v1_transfer_payload`]): output 0 = the user PDA with the exact
/// amount, at most one change output back to the company PDA, same mint, no
/// extra outputs, no compress/decompress (no burn), inputs == outputs
/// (overflow-checked), and the CPI authority must be the company PDA.
///
/// **NEW layout (backend story 3.41)** — mirror of `transfer_user_to_company`:
/// ```text
/// data:     company_id u64 | user_id u64 | amount u64 | company_bump u8 | user_bump u8
///           | memo String ("zupy:v1:<source>:<id>", REQUIRED) | V1 TRANSFER
/// accounts: 0 transfer_authority (signer) · 1 token_state · 2 mint · 3 company_pda
///           · 4 user_pda · 5 fee_payer · 6 system_program · 7 cToken (validated)
///           · 8+ V1 cToken CPI accounts (authority = company_pda)
/// ```
/// The memo is the operation id (e.g. `zupy:v1:ztransaction:<ledger id>`) and
/// lives in the data of the very instruction that moves the money, so a
/// payment of a specific ledger row is provable on-chain (story 3.35 found
/// the company → user carried none).
///
/// **LEGACY layout (what the backend sends up to 3.41, still accepted)**:
/// ```text
/// data:     company_id u64 | user_id u64 | company_bump u8 | user_bump u8 | V1 TRANSFER
/// accounts: 0..4 as above · 5+ V1 cToken CPI accounts (authority = company_pda)
/// ```
/// Detected by the V1 discriminator at byte 18. The amount is read from output 0
/// (which must be the user PDA and > 0); everything else is validated as in the
/// new layout. Unambiguous: in the new layout bytes 18..26 are the 6 high bytes of
/// `amount` + the two bumps, which would need `amount ≥ 3·2^56` lamports — far
/// above the whole supply. Dropping the legacy layout is a later upgrade, after
/// 3.41 is live (story 3.40, Q1 to the PO).
///
/// Discriminator: [8, 143, 213, 13, 143, 247, 145, 33] — UNCHANGED
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < C2U_BASE_ACCOUNTS {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let legacy = data.len() >= C2U_LEGACY_V1_OFFSET + 8
        && data[C2U_LEGACY_V1_OFFSET..C2U_LEGACY_V1_OFFSET + 8] == TRANSFER_V1_DISC;
    if legacy {
        process_legacy(program_id, accounts, data)
    } else {
        process_new(program_id, accounts, data)
    }
}

/// NEW layout: explicit `amount` + mandatory memo; accounts mirror user → company.
fn process_new(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < C2U_V1_CPI_ACCOUNTS_START {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let company_id = parse_u64(data, 0)?;
    let user_id = parse_u64(data, 8)?;
    let amount = parse_u64(data, 16)?;
    let company_bump = parse_u8(data, 24)?;
    let user_bump = parse_u8(data, 25)?;
    let (memo, v1_offset) = parse_string(data, 26)?;
    let v1_data = &data[v1_offset..];

    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_memo_format(memo)?;
    validate_transfer_common_compressed(program_id, &accounts[1], &accounts[0], &accounts[2])?;
    validate_light_ctoken_program(&accounts[7])?;

    let c2u = C2u { company_id, user_id, company_bump, user_bump, amount };
    c2u.validate_and_forward(program_id, accounts, &accounts[C2U_V1_CPI_ACCOUNTS_START..], v1_data)
}

/// LEGACY layout: no amount/memo in the header; the amount is output 0 of the payload.
fn process_legacy(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let company_id = parse_u64(data, 0)?;
    let user_id = parse_u64(data, 8)?;
    let company_bump = parse_u8(data, 16)?;
    let user_bump = parse_u8(data, 17)?;
    let v1_data = &data[C2U_LEGACY_V1_OFFSET..];

    let (_, amount) = v1_first_output(v1_data)?;
    if amount == 0 {
        return Err(ZupyTokenError::ZeroAmount.into());
    }
    validate_transfer_common_compressed(program_id, &accounts[1], &accounts[0], &accounts[2])?;

    let c2u = C2u { company_id, user_id, company_bump, user_bump, amount };
    c2u.validate_and_forward(program_id, accounts, &accounts[C2U_LEGACY_V1_CPI_ACCOUNTS_START..], v1_data)
}

/// Header fields both layouts share once parsed.
struct C2u {
    company_id: u64,
    user_id: u64,
    company_bump: u8,
    user_bump: u8,
    amount: u64,
}

impl C2u {
    /// PDAs, payload legs, CPI authority — then forward, signed by the company PDA.
    fn validate_and_forward(
        &self,
        program_id: &Address,
        accounts: &[AccountView],
        cpi_accounts: &[AccountView],
        v1_data: &[u8],
    ) -> ProgramResult {
        let mint = &accounts[2];
        let company_pda = &accounts[3]; // source PDA / CPI signer
        let user_pda = &accounts[4]; // destination PDA
        validate_id_pda(company_pda.address(), COMPANY_SEED, self.company_id, self.company_bump, program_id)?;
        validate_id_pda(user_pda.address(), USER_SEED, self.user_id, self.user_bump, program_id)?;

        // Output 0 = exactly `amount` to the user; change (if any) back to the company.
        let legs = [V1Leg { owner: user_pda.address(), amount: self.amount }];
        validate_v1_transfer_payload(v1_data, mint.address(), company_pda.address(), &legs)?;
        validate_v1_authority(cpi_accounts, company_pda)?;

        let company_id_bytes = self.company_id.to_le_bytes();
        let bump_bytes = [self.company_bump];
        let signer_seeds: [Seed; 3] = [
            Seed::from(COMPANY_SEED),
            Seed::from(company_id_bytes.as_ref()),
            Seed::from(bump_bytes.as_ref()),
        ];
        invoke_v1_transfer_signed(cpi_accounts, company_pda, v1_data, &[Signer::from(&signer_seeds)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_company_to_user_not_enough_account_keys() {
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 32];
        let result = process(&program_id, &[], &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    #[test]
    fn test_transfer_company_to_user_exactly_4_accounts_is_not_enough() {
        use pinocchio::account::{RuntimeAccount, NOT_BORROWED};
        let program_id = Address::from([1u8; 32]);
        let data = [0u8; 32];
        fn make_buf(addr: [u8; 32]) -> Vec<u64> {
            let words = (core::mem::size_of::<RuntimeAccount>() + 7) / 8 + 1;
            let mut buf = vec![0u64; words];
            let raw = buf.as_mut_ptr() as *mut RuntimeAccount;
            unsafe {
                (*raw).borrow_state = NOT_BORROWED;
                (*raw).address = Address::from(addr);
            }
            buf
        }
        let mut bufs: Vec<Vec<u64>> = (0..4).map(|i| make_buf([i as u8 + 1; 32])).collect();
        let accounts: Vec<AccountView> = bufs
            .iter_mut()
            .map(|b| unsafe { AccountView::new_unchecked(b.as_mut_ptr() as *mut RuntimeAccount) })
            .collect();
        let result = process(&program_id, &accounts, &data);
        assert_eq!(result.unwrap_err(), ProgramError::NotEnoughAccountKeys);
    }

    /// Short data buffer (< 18 bytes for V1 CPI data) must fail.
    #[test]
    fn test_transfer_company_to_user_short_data_returns_error() {
        let program_id = Address::default();
        let short_data = [0u8; 17];
        let result = process(&program_id, &[], &short_data);
        // Fails with NotEnoughAccountKeys (checked first)
        assert!(result.is_err());
    }
}
