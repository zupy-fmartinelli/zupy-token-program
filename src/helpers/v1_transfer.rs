//! V1 TRANSFER passthrough to the Light cToken program: validate, then forward.
//!
//! ## What was MEASURED (2026-09-29, story 3.21 — zupy-network)
//!
//! The mainnet cToken (`cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`) accepts the
//! Anchor `global:transfer` instruction (`[163,52,200,231,140,3,69,186]`) for
//! **compressed → compressed** transfers with a Groth16 validity proof:
//!
//! - Public mainnet tx `66bFvExdZpcnXirEXS1br2JoxL56Qk1yE7CAuDWvGabZmPSs9tcussJyRvZpvPRS4t7B7wKfqTNUPdak1mBHxYu8`
//!   (slot 451624459, 2026-09-29) is a SUCCESSFUL `transfer_company_to_user` that
//!   forwards exactly this V1 payload (outputs `[destination, change]`).
//! - The dispatch is present in the mainnet binary (sha256 `4d4575df…`) as an
//!   `lddw` immediate at offset `0x9cd68`. It is NOT present as 8 contiguous
//!   bytes — SBF stores a 64-bit immediate split in two 32-bit halves, so a
//!   plain byte search misses EVERY Anchor discriminator in the binary
//!   (`compress_spl_token_account`, which works on mainnet, included). That
//!   contiguous-byte search is what produced the old, wrong "V1 no longer
//!   present in the mainnet binary" comments.
//!
//! The cToken `Transfer` with disc=3 (see `cpi_compressed_transfer`) is a
//! different instruction: it moves **cToken Solana accounts** (decompressed,
//! owned by the cToken program). Z$ balances are **compressed leaves** owned by
//! our PDAs, so disc=3 fails with `Custom(18063) InvalidTokenOwner` (measured
//! by unsigned mainnet simulation in story 3.17).
//!
//! ## Why the program parses the payload
//!
//! Every instruction that signs a V1 TRANSFER with one of our PDAs checks that
//! the payload moves exactly the legs declared in the instruction header and
//! nothing else: [`validate_v1_transfer_payload`] for the client spends (3.21)
//! and, since story 3.40, for `transfer_company_to_user` too (it used to
//! forward the backend-built payload unread); [`validate_v1_consolidation_payload`]
//! for `consolidate_leaves` (N leaves of one owner → one leaf, same owner). The
//! program still decides no amount — it only refuses a payload that disagrees
//! with the legs it was handed.

use pinocchio::cpi::Signer;
use pinocchio::error::ProgramError;
use pinocchio::instruction::InstructionView;
use pinocchio::{AccountView, Address, ProgramResult};

use crate::constants::LIGHT_COMPRESSED_TOKEN_PROGRAM_ID;
use crate::error::ZupyTokenError;
use crate::helpers::compressed_accounts::{build_metas_forcing_signer, validate_v1_transfer_disc};
use crate::helpers::instruction_data::{parse_u32, parse_u64, parse_u8};

/// Upper bound on input leaves in one V1 transfer (bounds the parse loop).
/// Light's own client never batches more than 8 (proof batch sizes 1, 2, 3, 4, 8);
/// 8 leaves + proof fit in 857 B with the Light ALT (story 3.40, measured).
pub const MAX_V1_INPUTS: u32 = 8;

/// Fewest leaves a consolidation merges (one leaf is already consolidated).
pub const MIN_CONSOLIDATION_INPUTS: u32 = 2;

/// Size of a Groth16 `CompressedProof` (a:32 + b:64 + c:32).
const COMPRESSED_PROOF_LEN: usize = 128;

/// `PackedMerkleContext` (tree idx u8 + queue idx u8 + leaf_index u32 + prove_by_index bool)
/// followed by `root_index: u16`.
const MERKLE_CONTEXT_AND_ROOT_LEN: usize = 7 + 2;

/// One output the payload MUST contain, in order.
pub struct V1Leg<'a> {
    pub owner: &'a Address,
    pub amount: u64,
}

/// Forward-only Borsh reader over the inner `CompressedTokenInstructionDataTransfer`.
struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    #[inline(always)]
    fn u8(&mut self) -> Result<u8, ProgramError> {
        let v = parse_u8(self.data, self.offset)?;
        self.offset += 1;
        Ok(v)
    }

    #[inline(always)]
    fn u32(&mut self) -> Result<u32, ProgramError> {
        let v = parse_u32(self.data, self.offset)?;
        self.offset += 4;
        Ok(v)
    }

    #[inline(always)]
    fn u64(&mut self) -> Result<u64, ProgramError> {
        let v = parse_u64(self.data, self.offset)?;
        self.offset += 8;
        Ok(v)
    }

    #[inline(always)]
    fn skip(&mut self, n: usize) -> Result<(), ProgramError> {
        let end = self.offset.checked_add(n).ok_or(ProgramError::InvalidInstructionData)?;
        if end > self.data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.offset = end;
        Ok(())
    }

    #[inline(always)]
    fn pubkey(&mut self) -> Result<&'a [u8], ProgramError> {
        let start = self.offset;
        self.skip(32)?;
        Ok(&self.data[start..start + 32])
    }

    /// Borsh `Option` tag: 0 = None, 1 = Some, anything else is malformed.
    #[inline(always)]
    fn option_tag(&mut self) -> Result<bool, ProgramError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// The field must be `None` (these features are never used by Zupy).
    #[inline(always)]
    fn require_none(&mut self) -> Result<(), ProgramError> {
        if self.option_tag()? {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(())
    }

    #[inline(always)]
    fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }
}

/// Shape rules that differ between a spend and a consolidation.
#[derive(Clone, Copy)]
struct V1Shape {
    /// Fewest input leaves accepted (a consolidation of one leaf is a no-op).
    min_inputs: u32,
    /// Whether one change output back to the source owner may follow the legs.
    allow_change: bool,
}

/// Spend (story 3.21): 1..=8 inputs, legs + at most one change to the source.
const SPEND: V1Shape = V1Shape { min_inputs: 1, allow_change: true };

/// Consolidation (story 3.40): 2..=8 inputs, exactly ONE output, no change.
const CONSOLIDATION: V1Shape = V1Shape { min_inputs: MIN_CONSOLIDATION_INPUTS, allow_change: false };

/// Validate a V1 TRANSFER payload (`disc(8) | u32 len | Borsh`) before the
/// program signs it with `source_owner`'s PDA seeds.
///
/// Accepts exactly: optional proof, `mint`, no delegated transfer, 1..=8 inputs
/// (no delegate, no lamports, no TLV), outputs = `legs` in order (owner AND
/// amount) plus at most one change output owned by `source_owner`, no
/// compress/decompress, no CPI context, no lamports change, and an optional
/// trailing `with_transaction_hash` bool. Sum of inputs must equal sum of
/// outputs (overflow-checked) — money is conserved, never burned or minted.
/// `legs` must not be empty (review 3.21, deferred: the function refuses it
/// itself instead of trusting every caller).
pub fn validate_v1_transfer_payload(
    v1_data: &[u8],
    mint: &Address,
    source_owner: &Address,
    legs: &[V1Leg],
) -> Result<(), ProgramError> {
    validate_v1_payload(v1_data, mint, source_owner, legs, SPEND)
}

/// Validate a CONSOLIDATION payload (story 3.40): 2..=8 input leaves, all
/// spent by `owner` (the CPI authority, checked by the caller), and exactly one
/// output — to `owner`, of exactly `amount` — where `amount` equals the sum of
/// the inputs (overflow-checked). No fee leg, no change, no burn.
pub fn validate_v1_consolidation_payload(
    v1_data: &[u8],
    mint: &Address,
    owner: &Address,
    amount: u64,
) -> Result<(), ProgramError> {
    validate_v1_payload(v1_data, mint, owner, &[V1Leg { owner, amount }], CONSOLIDATION)
}

/// Open the `disc(8) | u32 len | Borsh` envelope and position a reader at the
/// start of the inner `CompressedTokenInstructionDataTransfer`.
fn open_v1(v1_data: &[u8]) -> Result<Reader<'_>, ProgramError> {
    validate_v1_transfer_disc(v1_data)?;
    let inner_len = parse_u32(v1_data, 8)? as usize;
    let inner = &v1_data[12..];
    if inner.len() != inner_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(Reader { data: inner, offset: 0 })
}

/// Read the header up to the inputs: proof (skipped), mint, delegated_transfer.
fn read_header<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], ProgramError> {
    // proof: Option<CompressedProof> — None is valid for prove-by-index inputs.
    if r.option_tag()? {
        r.skip(COMPRESSED_PROOF_LEN)?;
    }
    let mint = r.pubkey()?;
    r.require_none()?; // delegated_transfer
    Ok(mint)
}

fn validate_v1_payload(
    v1_data: &[u8],
    mint: &Address,
    source_owner: &Address,
    legs: &[V1Leg],
    shape: V1Shape,
) -> Result<(), ProgramError> {
    if legs.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut r = open_v1(v1_data)?;
    if read_header(&mut r)? != mint.as_ref() {
        return Err(ZupyTokenError::InvalidMint.into());
    }

    let inputs_total = read_inputs(&mut r, shape.min_inputs)?;
    let outputs_total = read_outputs(&mut r, source_owner, legs, shape.allow_change)?;

    if r.u8()? != 0 {
        return Err(ProgramError::InvalidInstructionData); // is_compress must be false
    }
    r.require_none()?; // compress_or_decompress_amount
    r.require_none()?; // cpi_context
    r.require_none()?; // lamports_change_account_merkle_tree_index
    match r.remaining() {
        [] | [0] | [1] => {} // optional with_transaction_hash: bool
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    let legs_total = legs.iter().try_fold(0u64, |acc, leg| {
        acc.checked_add(leg.amount).ok_or(ZupyTokenError::SplitCalculationError)
    })?;
    if inputs_total < legs_total {
        return Err(ZupyTokenError::InsufficientBalance.into());
    }
    if inputs_total != outputs_total {
        return Err(ZupyTokenError::SplitCalculationError.into());
    }
    Ok(())
}

/// Owner and amount of output 0 of a V1 payload — what the backend's current
/// `transfer_company_to_user` payload moves to the user (it declares no amount
/// in the header). Only reads; the caller still runs the full validation with
/// this amount as the leg, so a malformed tail is refused there.
pub fn v1_first_output(v1_data: &[u8]) -> Result<(&[u8], u64), ProgramError> {
    let mut r = open_v1(v1_data)?;
    read_header(&mut r)?;
    read_inputs(&mut r, 1)?;
    if r.u32()? == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let owner = r.pubkey()?;
    let amount = r.u64()?;
    Ok((owner, amount))
}

/// Read `input_token_data_with_context`, returning the overflow-checked sum.
fn read_inputs(r: &mut Reader, min_inputs: u32) -> Result<u64, ProgramError> {
    let count = r.u32()?;
    if count < min_inputs || count > MAX_V1_INPUTS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut total: u64 = 0;
    for _ in 0..count {
        let amount = r.u64()?;
        total = total.checked_add(amount).ok_or(ZupyTokenError::SplitCalculationError)?;
        r.require_none()?; // delegate_index
        r.skip(MERKLE_CONTEXT_AND_ROOT_LEN)?;
        r.require_none()?; // lamports
        r.require_none()?; // tlv
    }
    Ok(total)
}

/// Read `output_compressed_accounts`: `legs` in order, then (if `allow_change`)
/// at most one change output back to `source_owner`. Returns the
/// overflow-checked sum.
fn read_outputs(
    r: &mut Reader,
    source_owner: &Address,
    legs: &[V1Leg],
    allow_change: bool,
) -> Result<u64, ProgramError> {
    let count = r.u32()? as usize;
    let with_change = allow_change && count == legs.len() + 1;
    if count != legs.len() && !with_change {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut total: u64 = 0;
    for i in 0..count {
        let owner = r.pubkey()?;
        let amount = r.u64()?;
        r.require_none()?; // lamports
        r.u8()?; // merkle_tree_index — any tree/queue the client packed
        r.require_none()?; // tlv
        match legs.get(i) {
            Some(leg) => {
                if owner != leg.owner.as_ref() {
                    return Err(ZupyTokenError::InvalidPDA.into());
                }
                if amount != leg.amount {
                    return Err(ZupyTokenError::InvalidAmount.into());
                }
            }
            None if owner != source_owner.as_ref() => {
                return Err(ZupyTokenError::InvalidPDA.into());
            }
            None => {}
        }
        total = total.checked_add(amount).ok_or(ZupyTokenError::SplitCalculationError)?;
    }
    Ok(total)
}

/// The V1 CPI account list starts `[fee_payer, authority, ...]`. The authority
/// is who the cToken treats as owner of every input leaf, so it must be the
/// PDA whose seeds we sign with.
pub fn validate_v1_authority(cpi_accounts: &[AccountView], authority: &AccountView) -> Result<(), ProgramError> {
    let actual = cpi_accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if actual.address() != authority.address() {
        return Err(ZupyTokenError::InvalidPDA.into());
    }
    Ok(())
}

/// Forward a V1 TRANSFER to the cToken program, signing for `pda` via
/// `invoke_signed`. `pda` is not a signer on the outer transaction; its metas
/// are forced to signer so the runtime accepts the PDA signature.
///
/// Shared by `transfer_company_to_user`, `transfer_user_to_company`,
/// `execute_split_transfer` and the deprecated `return_*_v1` passthroughs.
#[inline(always)]
pub fn invoke_v1_transfer_signed(
    cpi_accounts: &[AccountView],
    pda: &AccountView,
    v1_data: &[u8],
    signers: &[Signer],
) -> ProgramResult {
    let prog_id: Address = LIGHT_COMPRESSED_TOKEN_PROGRAM_ID.into();
    let account_metas = build_metas_forcing_signer(cpi_accounts, pda);
    let instruction = InstructionView {
        program_id: &prog_id,
        accounts: &account_metas,
        data: v1_data,
    };
    let account_views: Vec<&AccountView> = cpi_accounts.iter().collect();
    pinocchio::cpi::invoke_signed_with_slice(&instruction, &account_views, signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::compressed_accounts::TRANSFER_V1_DISC;

    const MINT: [u8; 32] = [7u8; 32];
    const USER: [u8; 32] = [1u8; 32];
    const COMPANY: [u8; 32] = [2u8; 32];
    const POOL: [u8; 32] = [3u8; 32];

    struct Input {
        amount: u64,
        delegate: Option<u8>,
        lamports: Option<u64>,
        tlv: bool,
    }

    fn input(amount: u64) -> Input {
        Input { amount, delegate: None, lamports: None, tlv: false }
    }

    struct Output {
        owner: [u8; 32],
        amount: u64,
        lamports: Option<u64>,
        tlv: bool,
    }

    fn output(owner: [u8; 32], amount: u64) -> Output {
        Output { owner, amount, lamports: None, tlv: false }
    }

    struct Payload {
        proof: bool,
        mint: [u8; 32],
        delegated: bool,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        is_compress: u8,
        compress_amount: Option<u64>,
        cpi_context: bool,
        lamports_change: Option<u8>,
        tail: Vec<u8>,
    }

    fn payload(inputs: Vec<Input>, outputs: Vec<Output>) -> Payload {
        Payload {
            proof: true,
            mint: MINT,
            delegated: false,
            inputs,
            outputs,
            is_compress: 0,
            compress_amount: None,
            cpi_context: false,
            lamports_change: None,
            tail: vec![],
        }
    }

    /// Same byte layout the backend's `_build_v1_transfer_compressed_data`
    /// produces (and mainnet tx 66bFv… carries), generalized to N outputs.
    fn encode(p: &Payload) -> Vec<u8> {
        let mut inner = Vec::new();
        if p.proof {
            inner.push(1);
            inner.extend_from_slice(&[9u8; 128]);
        } else {
            inner.push(0);
        }
        inner.extend_from_slice(&p.mint);
        if p.delegated {
            inner.push(1);
            inner.extend_from_slice(&[4u8; 32]);
            inner.push(0);
        } else {
            inner.push(0);
        }
        inner.extend_from_slice(&(p.inputs.len() as u32).to_le_bytes());
        for i in &p.inputs {
            inner.extend_from_slice(&i.amount.to_le_bytes());
            match i.delegate {
                Some(d) => inner.extend_from_slice(&[1, d]),
                None => inner.push(0),
            }
            inner.extend_from_slice(&[0, 1]); // tree idx, queue idx
            inner.extend_from_slice(&42u32.to_le_bytes()); // leaf_index
            inner.push(0); // prove_by_index
            inner.extend_from_slice(&3u16.to_le_bytes()); // root_index
            match i.lamports {
                Some(l) => {
                    inner.push(1);
                    inner.extend_from_slice(&l.to_le_bytes());
                }
                None => inner.push(0),
            }
            if i.tlv {
                inner.extend_from_slice(&[1, 0, 0, 0, 0]);
            } else {
                inner.push(0);
            }
        }
        inner.extend_from_slice(&(p.outputs.len() as u32).to_le_bytes());
        for o in &p.outputs {
            inner.extend_from_slice(&o.owner);
            inner.extend_from_slice(&o.amount.to_le_bytes());
            match o.lamports {
                Some(l) => {
                    inner.push(1);
                    inner.extend_from_slice(&l.to_le_bytes());
                }
                None => inner.push(0),
            }
            inner.push(0); // merkle_tree_index
            if o.tlv {
                inner.extend_from_slice(&[1, 0, 0, 0, 0]);
            } else {
                inner.push(0);
            }
        }
        inner.push(p.is_compress);
        match p.compress_amount {
            Some(a) => {
                inner.push(1);
                inner.extend_from_slice(&a.to_le_bytes());
            }
            None => inner.push(0),
        }
        if p.cpi_context {
            inner.extend_from_slice(&[1, 0, 1, 0]);
        } else {
            inner.push(0);
        }
        match p.lamports_change {
            Some(i) => inner.extend_from_slice(&[1, i]),
            None => inner.push(0),
        }
        inner.extend_from_slice(&p.tail);

        let mut data = Vec::from(TRANSFER_V1_DISC.as_slice());
        data.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        data.extend_from_slice(&inner);
        data
    }

    fn addr(b: [u8; 32]) -> Address {
        Address::from(b)
    }

    fn split_legs<'a>(company: &'a Address, pool: &'a Address, c: u64, p: u64) -> Vec<V1Leg<'a>> {
        let mut legs = vec![V1Leg { owner: company, amount: c }];
        if p > 0 {
            legs.push(V1Leg { owner: pool, amount: p });
        }
        legs
    }

    fn check(p: &Payload, c: u64, pool: u64) -> Result<(), ProgramError> {
        let (mint, user, company, pool_addr) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = split_legs(&company, &pool_addr, c, pool);
        validate_v1_transfer_payload(&encode(p), &mint, &user, &legs)
    }

    fn custom(e: ZupyTokenError) -> Result<(), ProgramError> {
        Err(ProgramError::Custom(e as u32))
    }

    // ── Happy paths ─────────────────────────────────────────────────────────

    #[test]
    fn split_with_change_is_valid() {
        let p = payload(
            vec![input(1_000)],
            vec![output(COMPANY, 800), output(POOL, 40), output(USER, 160)],
        );
        assert_eq!(check(&p, 800, 40), Ok(()));
    }

    #[test]
    fn split_spending_the_whole_leaf_needs_no_change() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Ok(()));
    }

    #[test]
    fn pool_zero_means_no_pool_output() {
        let p = payload(vec![input(1_000)], vec![output(COMPANY, 800), output(USER, 200)]);
        assert_eq!(check(&p, 800, 0), Ok(()));
    }

    #[test]
    fn several_inputs_are_summed() {
        let p = payload(
            vec![input(500), input(500)],
            vec![output(COMPANY, 800), output(POOL, 40), output(USER, 160)],
        );
        assert_eq!(check(&p, 800, 40), Ok(()));
    }

    #[test]
    fn proof_none_is_accepted_for_prove_by_index_inputs() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.proof = false;
        assert_eq!(check(&p, 800, 40), Ok(()));
    }

    #[test]
    fn trailing_with_transaction_hash_bool_is_accepted() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.tail = vec![1];
        assert_eq!(check(&p, 800, 40), Ok(()));
    }

    // ── Envelope ────────────────────────────────────────────────────────────

    #[test]
    fn empty_payload_is_rejected() {
        let (mint, user) = (addr(MINT), addr(USER));
        assert_eq!(
            validate_v1_transfer_payload(&[], &mint, &user, &[]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn wrong_discriminator_is_rejected() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        let mut data = encode(&p);
        data[0] ^= 0xff;
        let (mint, user, company, pool) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = split_legs(&company, &pool, 800, 40);
        assert_eq!(
            validate_v1_transfer_payload(&data, &mint, &user, &legs),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn length_prefix_must_match() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        let mut data = encode(&p);
        data.push(0); // one byte more than the Vec<u8> prefix says
        let (mint, user, company, pool) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = split_legs(&company, &pool, 800, 40);
        assert_eq!(
            validate_v1_transfer_payload(&data, &mint, &user, &legs),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        let mut data = encode(&p);
        data.truncate(data.len() - 3);
        let len = (data.len() - 12) as u32;
        data[8..12].copy_from_slice(&len.to_le_bytes());
        let (mint, user, company, pool) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = split_legs(&company, &pool, 800, 40);
        assert_eq!(
            validate_v1_transfer_payload(&data, &mint, &user, &legs),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn bad_option_tag_is_rejected() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        let mut data = encode(&p);
        data[12] = 2; // proof Option tag
        let (mint, user, company, pool) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = split_legs(&company, &pool, 800, 40);
        assert_eq!(
            validate_v1_transfer_payload(&data, &mint, &user, &legs),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    // ── Header fields ───────────────────────────────────────────────────────

    #[test]
    fn wrong_mint_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.mint = [8u8; 32];
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidMint));
    }

    #[test]
    fn delegated_transfer_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.delegated = true;
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    // ── Inputs ──────────────────────────────────────────────────────────────

    #[test]
    fn zero_inputs_are_rejected() {
        let p = payload(vec![], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn more_than_max_inputs_are_rejected() {
        let inputs = (0..=MAX_V1_INPUTS).map(|_| input(1)).collect();
        let p = payload(inputs, vec![output(COMPANY, 9)]);
        assert_eq!(check(&p, 9, 0), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn input_with_delegate_is_rejected() {
        let mut i = input(840);
        i.delegate = Some(3);
        let p = payload(vec![i], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn input_with_lamports_is_rejected() {
        let mut i = input(840);
        i.lamports = Some(5);
        let p = payload(vec![i], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn input_with_tlv_is_rejected() {
        let mut i = input(840);
        i.tlv = true;
        let p = payload(vec![i], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn input_sum_overflow_is_rejected() {
        let p = payload(vec![input(u64::MAX), input(1)], vec![output(COMPANY, 1)]);
        assert_eq!(check(&p, 1, 0), custom(ZupyTokenError::SplitCalculationError));
    }

    // ── Outputs ─────────────────────────────────────────────────────────────

    #[test]
    fn missing_pool_output_is_rejected() {
        let p = payload(vec![input(1_000)], vec![output(COMPANY, 800), output(USER, 200)]);
        // legs say pool=40 → output[1] must be the pool, not the user
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidPDA));
    }

    #[test]
    fn too_few_outputs_are_rejected() {
        let p = payload(vec![input(800)], vec![output(COMPANY, 800)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn extra_outputs_beyond_one_change_are_rejected() {
        let p = payload(
            vec![input(1_000)],
            vec![output(COMPANY, 800), output(POOL, 40), output(USER, 80), output(USER, 80)],
        );
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn company_output_to_wrong_owner_is_rejected() {
        let p = payload(vec![input(840)], vec![output([5u8; 32], 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidPDA));
    }

    #[test]
    fn company_output_with_other_amount_is_rejected() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 801), output(POOL, 39)]);
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidAmount));
    }

    #[test]
    fn pool_output_with_other_amount_is_rejected() {
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 41)]);
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidAmount));
    }

    #[test]
    fn change_to_someone_else_is_rejected() {
        let p = payload(
            vec![input(1_000)],
            vec![output(COMPANY, 800), output(POOL, 40), output([5u8; 32], 160)],
        );
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InvalidPDA));
    }

    #[test]
    fn output_with_lamports_is_rejected() {
        let mut o = output(COMPANY, 800);
        o.lamports = Some(1);
        let p = payload(vec![input(840)], vec![o, output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn output_with_tlv_is_rejected() {
        let mut o = output(POOL, 40);
        o.tlv = true;
        let p = payload(vec![input(840)], vec![output(COMPANY, 800), o]);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn output_sum_overflow_is_rejected() {
        let p = payload(vec![input(1)], vec![output(COMPANY, u64::MAX), output(USER, 1)]);
        assert_eq!(check(&p, u64::MAX, 0), custom(ZupyTokenError::SplitCalculationError));
    }

    #[test]
    fn legs_sum_overflow_is_rejected() {
        let p = payload(vec![input(1)], vec![output(COMPANY, u64::MAX), output(POOL, 1)]);
        let (mint, user, company, pool) = (addr(MINT), addr(USER), addr(COMPANY), addr(POOL));
        let legs = [V1Leg { owner: &company, amount: u64::MAX }, V1Leg { owner: &pool, amount: 1 }];
        assert_eq!(
            validate_v1_transfer_payload(&encode(&p), &mint, &user, &legs),
            custom(ZupyTokenError::SplitCalculationError)
        );
    }

    // ── Conservation ────────────────────────────────────────────────────────

    #[test]
    fn inputs_smaller_than_legs_is_insufficient_balance() {
        let p = payload(vec![input(500)], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::InsufficientBalance));
    }

    #[test]
    fn missing_change_would_burn_and_is_rejected() {
        // 1_000 in, 840 out: 160 would vanish (a burn). Money is conserved.
        let p = payload(vec![input(1_000)], vec![output(COMPANY, 800), output(POOL, 40)]);
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::SplitCalculationError));
    }

    #[test]
    fn change_larger_than_remainder_would_mint_and_is_rejected() {
        let p = payload(
            vec![input(1_000)],
            vec![output(COMPANY, 800), output(POOL, 40), output(USER, 161)],
        );
        assert_eq!(check(&p, 800, 40), custom(ZupyTokenError::SplitCalculationError));
    }

    // ── Tail flags ──────────────────────────────────────────────────────────

    #[test]
    fn compress_flag_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.is_compress = 1;
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn decompress_amount_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.compress_amount = Some(10);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn cpi_context_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.cpi_context = true;
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn lamports_change_index_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.lamports_change = Some(0);
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.tail = vec![1, 2];
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn trailing_non_bool_is_rejected() {
        let mut p = payload(vec![input(840)], vec![output(COMPANY, 800), output(POOL, 40)]);
        p.tail = vec![2];
        assert_eq!(check(&p, 800, 40), Err(ProgramError::InvalidInstructionData));
    }

    // ── Consolidation (story 3.40): N leaves of ONE owner → ONE leaf ────────

    fn consolidate(p: &Payload, declared: u64) -> Result<(), ProgramError> {
        let (mint, user) = (addr(MINT), addr(USER));
        validate_v1_consolidation_payload(&encode(p), &mint, &user, declared)
    }

    #[test]
    fn consolidation_of_two_leaves_is_valid() {
        let p = payload(vec![input(300), input(700)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), Ok(()));
    }

    #[test]
    fn consolidation_of_eight_leaves_is_valid() {
        let p = payload((1..=8).map(input).collect(), vec![output(USER, 36)]);
        assert_eq!(consolidate(&p, 36), Ok(()));
    }

    #[test]
    fn consolidation_of_a_single_leaf_is_rejected() {
        let p = payload(vec![input(1_000)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn consolidation_of_nine_leaves_is_rejected() {
        let p = payload((1..=9).map(input).collect(), vec![output(USER, 45)]);
        assert_eq!(consolidate(&p, 45), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn consolidation_with_two_outputs_is_rejected_even_to_the_owner() {
        let p = payload(vec![input(500), input(500)], vec![output(USER, 600), output(USER, 400)]);
        assert_eq!(consolidate(&p, 600), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn consolidation_without_output_is_rejected() {
        let p = payload(vec![input(500), input(500)], vec![]);
        assert_eq!(consolidate(&p, 1_000), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn consolidation_to_another_owner_is_rejected() {
        let p = payload(vec![input(500), input(500)], vec![output(COMPANY, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), custom(ZupyTokenError::InvalidPDA));
    }

    #[test]
    fn consolidation_output_other_than_declared_is_rejected() {
        let p = payload(vec![input(500), input(500)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 999), custom(ZupyTokenError::InvalidAmount));
    }

    #[test]
    fn consolidation_with_inputs_short_of_declared_is_insufficient_balance() {
        let p = payload(vec![input(500), input(400)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), custom(ZupyTokenError::InsufficientBalance));
    }

    #[test]
    fn consolidation_that_would_burn_the_excess_is_rejected() {
        let p = payload(vec![input(600), input(500)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), custom(ZupyTokenError::SplitCalculationError));
    }

    #[test]
    fn consolidation_with_wrong_mint_is_rejected() {
        let mut p = payload(vec![input(500), input(500)], vec![output(USER, 1_000)]);
        p.mint = [8u8; 32];
        assert_eq!(consolidate(&p, 1_000), custom(ZupyTokenError::InvalidMint));
    }

    #[test]
    fn consolidation_input_overflow_is_rejected() {
        let p = payload(vec![input(u64::MAX), input(1)], vec![output(USER, 1)]);
        assert_eq!(consolidate(&p, 1), custom(ZupyTokenError::SplitCalculationError));
    }

    #[test]
    fn consolidation_with_decompress_is_rejected() {
        let mut p = payload(vec![input(500), input(500)], vec![output(USER, 1_000)]);
        p.compress_amount = Some(1);
        assert_eq!(consolidate(&p, 1_000), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn consolidation_input_with_delegate_is_rejected() {
        let mut i = input(500);
        i.delegate = Some(0);
        let p = payload(vec![i, input(500)], vec![output(USER, 1_000)]);
        assert_eq!(consolidate(&p, 1_000), Err(ProgramError::InvalidInstructionData));
    }

    // ── Shared guard (review 3.21, deferred): no legs = nothing to execute ──

    #[test]
    fn empty_legs_are_rejected() {
        let p = payload(vec![input(1_000)], vec![output(USER, 1_000)]);
        let (mint, user) = (addr(MINT), addr(USER));
        assert_eq!(
            validate_v1_transfer_payload(&encode(&p), &mint, &user, &[]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    // ── First output (legacy transfer_company_to_user layout, story 3.40) ──

    #[test]
    fn first_output_is_read_from_the_payload() {
        let p = payload(vec![input(1_000), input(5)], vec![output(COMPANY, 800), output(USER, 205)]);
        let data = encode(&p);
        let (owner, amount) = v1_first_output(&data).unwrap();
        assert_eq!((owner, amount), (&COMPANY[..], 800));
    }

    #[test]
    fn first_output_of_a_payload_without_outputs_is_rejected() {
        let p = payload(vec![input(1_000)], vec![]);
        assert_eq!(v1_first_output(&encode(&p)), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn first_output_of_a_truncated_payload_is_rejected() {
        let p = payload(vec![input(1_000)], vec![output(COMPANY, 800)]);
        let data = encode(&p);
        assert_eq!(v1_first_output(&data[..60]), Err(ProgramError::InvalidInstructionData));
    }

    #[test]
    fn first_output_requires_the_v1_discriminator() {
        let p = payload(vec![input(1_000)], vec![output(COMPANY, 800)]);
        let mut data = encode(&p);
        data[0] ^= 0xff;
        assert_eq!(v1_first_output(&data), Err(ProgramError::InvalidInstructionData));
    }

    // ── Real mainnet payload ────────────────────────────────────────────────

    /// The V1 payload of mainnet tx 66bFvExd…YxHu8 (a SUCCESSFUL
    /// transfer_company_to_user, 2026-09-29) passes the validator with the
    /// legs it actually moved: 10.000000 Z$ to the user PDA, change to company.
    #[test]
    fn real_mainnet_transfer_company_to_user_payload_is_valid() {
        let hex = "a334c8e78c0345ba18010000010674935c948c690545a63cec4e9ed517f6ab571ba0ded49e559feed0cea43ad995ed4fde64e0f5f42fb0b16e7b28223697848a7b00a5fbdc2bd13a921f0ae836136840796447aff3b98b63c00451d2612e2b5acc845e9a0b4d7cd150e967004410384a22d70e947907cb36dbb26c8db98d731679b0272e27446075a422f2b16208518df4bb303ef82ba6deeed37357c1bd53cf3141b0ba6e2ae08c2d549b0b94000100000080033005010000000000015b989403005b08000002000000fdb4db4b8bbf5a1087d1dd96ed74baf97794780ff2e8b7262a1e98cbb4c81ff38096980000000000000000503d028181da71668b99d5aa571746135ab090ce7e038206c4ee26256be8c3a7006d97040100000000000000000000";
        let data: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        // mint ZUPYxKLj…, user_pda J5N6gq3…, company_pda 6QDaFCi… — read from
        // the payload's own fields so the test stays a pure fixture.
        let mint = Address::from(<[u8; 32]>::try_from(&data[12 + 129..12 + 161]).unwrap());
        let out0 = 12 + 161 + 1 + 4 + 20 + 4;
        let user = Address::from(<[u8; 32]>::try_from(&data[out0..out0 + 32]).unwrap());
        let company = Address::from(<[u8; 32]>::try_from(&data[out0 + 43..out0 + 75]).unwrap());
        let legs = [V1Leg { owner: &user, amount: 10_000_000 }];
        assert_eq!(validate_v1_transfer_payload(&data, &mint, &company, &legs), Ok(()));
    }
}
