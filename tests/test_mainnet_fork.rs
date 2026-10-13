//! Client-spend transfers against the REAL mainnet Light Protocol binaries (story 3.21).
//!
//! Basic Mollusk has no cToken, so the unit/Mollusk suites stop at "the CPI was
//! attempted". This file loads the programs dumped read-only from mainnet —
//! cToken, Light system, account compression, noop, Token-2022 — plus the real
//! ZUPY mint, `token_state`, cToken authorities and the V2 batched state tree
//! `bmt1…` / output queue `oq1…`, and runs OUR freshly built program
//! (`target/deploy`, `--features mainnet`) against them.
//!
//! Why V2 tree + prove-by-index: a leaf in the V2 output queue can be spent
//! without a Groth16 proof (`prove_by_index = true`), so no prover/Photon is
//! needed. The instruction layout our program forwards is the same V1 TRANSFER
//! the backend sends for V1-tree leaves (which carry a proof instead) — the
//! program never interprets the proof, the cToken/Light system do.
//!
//! Proof BY EFFECT (GR28): after a split, each output leaf is spent by its owner
//! with its exact amount; a leaf with any other owner/amount does not exist and
//! the spend fails. The spent input leaf cannot be spent twice.
//!
//! Run (needs fixtures + a fresh mainnet build):
//!   scripts/fetch-mainnet-fixtures.sh
//!   cargo build-sbf --no-default-features --features mainnet
//!   SBF_OUT_DIR=target/deploy cargo test --test test_mainnet_fork -- --ignored --test-threads=1 --nocapture

mod helpers;
use helpers::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

use mollusk_svm::program::loader_keys::LOADER_V3;
use mollusk_svm::result::InstructionResult;
use mollusk_svm::{Mollusk, MolluskContext};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const DISC_SPLIT: [u8; 8] = [51, 254, 61, 214, 234, 138, 101, 214];
const DISC_U2C: [u8; 8] = [186, 233, 22, 40, 87, 223, 252, 131];
const DISC_C2U: [u8; 8] = [8, 143, 213, 13, 143, 247, 145, 33];
const DISC_CONSOLIDATE: [u8; 8] = [131, 243, 51, 130, 117, 203, 4, 156];
const OWNER_USER: u8 = 0;
const OWNER_COMPANY: u8 = 1;

// Real mainnet ids (public; the same pair the 3.17 simulation used).
const USER_ID: u64 = 2_140_389_439_281_718_293;
const COMPANY_ID: u64 = 9_068_097_475_314_820_308;

fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}

fn ctoken() -> Pubkey { pk("cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m") }
fn light_system() -> Pubkey { pk("SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7") }
fn account_compression() -> Pubkey { pk("compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq") }
fn noop() -> Pubkey { pk("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV") }
fn token_2022() -> Pubkey { pk("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb") }
fn zupy_mint() -> Pubkey { pk("ZUPYxKLjfRyRmoF6j8Su8D3aTDkB4k4uqXLqHn8wcao") }
fn token_state() -> Pubkey { pk("6UNF7ECPmEmKrvgpH6abi6XcGmSASvJU9vaDjGgzMVYP") }
fn transfer_authority() -> Pubkey { pk("ZUPYtXrbnstMAZP5c4V6kzok9eTrGyGBbwpPdte1QSd") }
fn cpi_authority() -> Pubkey { pk("GXtd2izAiMJPwMEjfgTRH3d7k9mjn4Jq3JrWFv9gySYy") }
fn registered_program() -> Pubkey { pk("35hkDgaAKwMCaxRz2ocSZ6NaUrtKkyNqU6c4RV3tYJRh") }
fn compression_authority() -> Pubkey { pk("HwXnGK3tPkkVY6P439H2p68AxpeuWXd5PcrAxFpbmfbA") }
fn tree() -> Pubkey { pk("bmt1LryLZUMmF7ZtqESaw7wifBXLfXHQYoE4GAmrahU") }
fn queue() -> Pubkey { pk("oq1na8gojfdUhsfCpyjNt6h4JaDWtHf1yQj4koBWfto") }
fn spl_pool() -> Pubkey { pk("E7JkVUvoGjv1MAJAPgJ7Vh8NnGC5kAHYd1Sndzyb2fYM") }
fn system() -> Pubkey { Pubkey::default() }

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mainnet")
}

fn load_account(key: &Pubkey) -> Account {
    let base = fixtures().join("accounts").join(key.to_string());
    let data = std::fs::read(base.with_extension("bin"))
        .unwrap_or_else(|_| panic!("missing fixture for {key} — run scripts/fetch-mainnet-fixtures.sh"));
    let meta = std::fs::read_to_string(base.with_extension("meta")).unwrap();
    let mut it = meta.split_whitespace();
    let owner = pk(it.next().unwrap());
    let lamports: u64 = it.next().unwrap().parse().unwrap();
    Account { lamports, data, owner, executable: false, rent_epoch: u64::MAX }
}

struct Fork {
    ctx: MolluskContext<HashMap<Pubkey, Account>>,
    store: Rc<RefCell<HashMap<Pubkey, Account>>>,
    user_pda: Pubkey,
    user_bump: u8,
    company_pda: Pubkey,
    company_bump: u8,
    pool_pda: Pubkey,
    pool_bump: u8,
}

fn fork() -> Fork {
    let mut mollusk = Mollusk::new(&program_id(), "zupy_token_program");
    for id in [ctoken(), light_system(), account_compression(), noop(), token_2022()] {
        let elf = std::fs::read(fixtures().join("programs").join(format!("{id}.so")))
            .unwrap_or_else(|_| panic!("missing program {id} — run scripts/fetch-mainnet-fixtures.sh"));
        mollusk.add_program_with_loader_and_elf(&id, &LOADER_V3, &elf);
    }
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    let mut store: HashMap<Pubkey, Account> = HashMap::new();
    for key in [zupy_mint(), token_state(), cpi_authority(), registered_program(), tree(), queue(), spl_pool()] {
        store.insert(key, load_account(&key));
    }
    store.insert(transfer_authority(), Account { lamports: 10_000_000_000, owner: system(), ..Account::default() });

    let (user_pda, user_bump) = derive_user_pda(USER_ID);
    let (company_pda, company_bump) = derive_company_pda(COMPANY_ID);
    let (pool_pda, pool_bump) = derive_incentive_pool_pda();
    assert_eq!(user_pda, pk("J5N6gq3W5awSnLq5tfWszFGQ7fQrb8XfkyDTWsCwGnTc"), "mainnet user PDA");
    assert_eq!(company_pda, pk("6QDaFCi7aEpufVybjxYXceKRxd9L5aQHg93XpgyidTCJ"), "mainnet company PDA");

    let ctx = mollusk.with_context(store);
    let store = Rc::clone(&ctx.account_store);
    Fork { ctx, store, user_pda, user_bump, company_pda, company_bump, pool_pda, pool_bump }
}

impl Fork {
    /// `next_index` of the V2 output queue = index the next output leaf gets.
    fn next_leaf_index(&self) -> u32 {
        let mut data = self.store.borrow().get(&queue()).unwrap().data.clone();
        let q = light_batched_merkle_tree::queue::BatchedQueueAccount::output_from_bytes(&mut data).unwrap();
        q.get_metadata().batch_metadata.next_index as u32
    }

    /// V1 cToken CPI accounts, same order the backend sends for
    /// `transfer_company_to_user`; `authority` = the PDA whose leaves are spent.
    fn v1_cpi_accounts(&self, authority: &Pubkey, authority_is_signer: bool) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(transfer_authority(), true),                 // fee_payer
            AccountMeta { pubkey: *authority, is_signer: authority_is_signer, is_writable: false },
            AccountMeta::new_readonly(cpi_authority(), false),
            AccountMeta::new_readonly(light_system(), false),
            AccountMeta::new_readonly(registered_program(), false),
            AccountMeta::new_readonly(noop(), false),
            AccountMeta::new_readonly(compression_authority(), false),
            AccountMeta::new_readonly(account_compression(), false),
            AccountMeta::new_readonly(ctoken(), false),                   // self_program
            AccountMeta::new(ctoken(), false),                            // token_pool: None
            AccountMeta::new(ctoken(), false),                            // compress/decompress acct: None
            AccountMeta::new_readonly(ctoken(), false),                   // token_program: None
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new(tree(), false),                              // remaining[0]
            AccountMeta::new(queue(), false),                             // remaining[1]
        ]
    }

    /// Put `amount` Z$ into a fresh compressed leaf owned by `owner` (cToken V1
    /// transfer with `is_compress`, from a Token-2022 account we fabricate by
    /// cloning the real SPL pool account). Returns the leaf index.
    fn mint_leaf(&self, owner: &Pubkey, amount: u64) -> u32 {
        let holder = Pubkey::new_unique();
        let holder_ata = Pubkey::new_unique();
        let mut ata = self.store.borrow().get(&spl_pool()).unwrap().clone();
        ata.data[32..64].copy_from_slice(holder.as_ref()); // owner
        ata.data[64..72].copy_from_slice(&amount.to_le_bytes()); // amount
        self.store.borrow_mut().insert(holder_ata, ata);

        let mut inner = Vec::new();
        inner.push(0); // proof: None
        inner.extend_from_slice(zupy_mint().as_ref());
        inner.push(0); // delegated_transfer: None
        inner.extend_from_slice(&0u32.to_le_bytes()); // no inputs
        inner.extend_from_slice(&1u32.to_le_bytes()); // one output
        inner.extend_from_slice(owner.as_ref());
        inner.extend_from_slice(&amount.to_le_bytes());
        inner.extend_from_slice(&[0, 0, 0]); // lamports None, tree idx 0 (= oq1), tlv None
        inner.push(1); // is_compress
        inner.push(1);
        inner.extend_from_slice(&amount.to_le_bytes()); // compress amount
        inner.extend_from_slice(&[0, 0]); // cpi_context None, lamports change None
        let mut data = Vec::from(V1_TRANSFER_DISC.as_slice());
        data.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        data.extend_from_slice(&inner);

        let accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(holder, true),
            AccountMeta::new_readonly(cpi_authority(), false),
            AccountMeta::new_readonly(light_system(), false),
            AccountMeta::new_readonly(registered_program(), false),
            AccountMeta::new_readonly(noop(), false),
            AccountMeta::new_readonly(compression_authority(), false),
            AccountMeta::new_readonly(account_compression(), false),
            AccountMeta::new_readonly(ctoken(), false),
            AccountMeta::new(spl_pool(), false),
            AccountMeta::new(holder_ata, false),
            AccountMeta::new_readonly(token_2022(), false),
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new(queue(), false),
        ];
        let index = self.next_leaf_index();
        let r = self.ctx.process_instruction(&Instruction::new_with_bytes(ctoken(), &data, accounts));
        assert!(r.program_result.is_ok(), "compress setup failed: {:?}", r.raw_result);
        assert_eq!(self.next_leaf_index(), index + 1);
        index
    }

    fn input(amount: u64, leaf_index: u32) -> V1Input {
        V1Input { amount, tree_index: 0, queue_index: 1, leaf_index, prove_by_index: true, root_index: 0 }
    }

    fn split(&self, company: u64, pool: u64, v1: &[u8]) -> InstructionResult {
        let mut payload = Vec::new();
        payload.extend_from_slice(&USER_ID.to_le_bytes());
        payload.extend_from_slice(&COMPANY_ID.to_le_bytes());
        payload.extend_from_slice(&company.to_le_bytes());
        payload.extend_from_slice(&pool.to_le_bytes());
        payload.extend_from_slice(&[self.user_bump, self.company_bump, self.pool_bump]);
        payload.extend_from_slice(&build_string("z_direct"));
        payload.extend_from_slice(v1);
        let mut accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(token_state(), false),
            AccountMeta::new_readonly(zupy_mint(), false),
            AccountMeta::new_readonly(self.user_pda, false),
            AccountMeta::new_readonly(self.company_pda, false),
            AccountMeta::new_readonly(self.pool_pda, false),
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new_readonly(ctoken(), false),
        ];
        accounts.extend(self.v1_cpi_accounts(&self.user_pda, false));
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            program_id(), &build_ix_data(&DISC_SPLIT, &payload), accounts,
        ))
    }

    fn user_to_company(&self, amount: u64, v1: &[u8]) -> InstructionResult {
        let mut payload = Vec::new();
        payload.extend_from_slice(&USER_ID.to_le_bytes());
        payload.extend_from_slice(&COMPANY_ID.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&[self.user_bump, self.company_bump]);
        payload.extend_from_slice(&build_string("zupy:v1:u2c:fork"));
        payload.extend_from_slice(v1);
        let mut accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(token_state(), false),
            AccountMeta::new_readonly(zupy_mint(), false),
            AccountMeta::new_readonly(self.user_pda, false),
            AccountMeta::new_readonly(self.company_pda, false),
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new_readonly(ctoken(), false),
        ];
        accounts.extend(self.v1_cpi_accounts(&self.user_pda, false));
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            program_id(), &build_ix_data(&DISC_U2C, &payload), accounts,
        ))
    }

    /// `transfer_company_to_user` in the LEGACY layout (removed in story 36.6):
    /// built only to prove the program refuses it.
    fn company_to_user_legacy(&self, v1: &[u8]) -> InstructionResult {
        let mut payload = Vec::new();
        payload.extend_from_slice(&COMPANY_ID.to_le_bytes());
        payload.extend_from_slice(&USER_ID.to_le_bytes());
        payload.extend_from_slice(&[self.company_bump, self.user_bump]);
        payload.extend_from_slice(v1);
        let mut accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(token_state(), false),
            AccountMeta::new_readonly(zupy_mint(), false),
            AccountMeta::new_readonly(self.company_pda, false),
            AccountMeta::new_readonly(self.user_pda, false),
        ];
        accounts.extend(self.v1_cpi_accounts(&self.company_pda, false));
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            program_id(), &build_ix_data(&DISC_C2U, &payload), accounts,
        ))
    }

    /// `transfer_company_to_user` (the only layout since story 36.6): explicit
    /// amount + memo, accounts mirror user → company, CPI tail from [8].
    fn company_to_user_new(&self, amount: u64, memo: &str, v1: &[u8]) -> InstructionResult {
        let mut payload = Vec::new();
        payload.extend_from_slice(&COMPANY_ID.to_le_bytes());
        payload.extend_from_slice(&USER_ID.to_le_bytes());
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&[self.company_bump, self.user_bump]);
        payload.extend_from_slice(&build_string(memo));
        payload.extend_from_slice(v1);
        let mut accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(token_state(), false),
            AccountMeta::new_readonly(zupy_mint(), false),
            AccountMeta::new_readonly(self.company_pda, false),
            AccountMeta::new_readonly(self.user_pda, false),
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(system(), false),
            AccountMeta::new_readonly(ctoken(), false),
        ];
        accounts.extend(self.v1_cpi_accounts(&self.company_pda, false));
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            program_id(), &build_ix_data(&DISC_C2U, &payload), accounts,
        ))
    }

    /// `consolidate_leaves` (story 3.40) for the user or the company PDA.
    fn consolidate(&self, kind: u8, amount: u64, v1: &[u8]) -> InstructionResult {
        let (id, bump, owner) = if kind == OWNER_COMPANY {
            (COMPANY_ID, self.company_bump, self.company_pda)
        } else {
            (USER_ID, self.user_bump, self.user_pda)
        };
        let mut payload = vec![kind];
        payload.extend_from_slice(&id.to_le_bytes());
        payload.push(bump);
        payload.extend_from_slice(&amount.to_le_bytes());
        payload.extend_from_slice(&build_string("zupy:v1:consolidate:fork"));
        payload.extend_from_slice(v1);
        let mut accounts = vec![
            AccountMeta::new(transfer_authority(), true),
            AccountMeta::new_readonly(token_state(), false),
            AccountMeta::new_readonly(zupy_mint(), false),
            AccountMeta::new_readonly(owner, false),
        ];
        accounts.extend(self.v1_cpi_accounts(&owner, false));
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            program_id(), &build_ix_data(&DISC_CONSOLIDATE, &payload), accounts,
        ))
    }

    /// Mint `amounts.len()` fresh leaves to `owner`; returns their inputs.
    fn mint_leaves(&self, owner: &Pubkey, amounts: &[u64]) -> Vec<V1Input> {
        amounts.iter().map(|a| Self::input(*a, self.mint_leaf(owner, *a))).collect()
    }

    /// Spend a pool-owned leaf directly at the cToken (Mollusk does not verify
    /// signatures, so the pool PDA can be marked signer) — effect probe only.
    fn pool_self_transfer(&self, amount: u64, leaf_index: u32) -> InstructionResult {
        let v1 = build_v1_transfer(
            &zupy_mint(), None, &[Self::input(amount, leaf_index)], &[(self.pool_pda, amount, 1)],
        );
        self.ctx.process_instruction(&Instruction::new_with_bytes(
            ctoken(), &v1, self.v1_cpi_accounts(&self.pool_pda, true),
        ))
    }
}

fn ok(r: &InstructionResult, what: &str) {
    assert!(r.program_result.is_ok(), "{what} failed: {:?}", r.raw_result);
}

fn err(r: &InstructionResult, what: &str) {
    assert!(r.program_result.is_err(), "{what} unexpectedly succeeded");
}

/// Split user → company 800 + pool 40 + change 160 (Z$, 6 decimals) in ONE
/// V1 CPI signed by the user PDA, against the real mainnet binaries.
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn split_moves_exact_legs_with_real_ctoken() {
    let f = fork();
    let leaf = f.mint_leaf(&f.user_pda, 1_000_000_000);
    let (c, p, change) = (800_000_000u64, 40_000_000u64, 160_000_000u64);

    let v1 = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(1_000_000_000, leaf)],
        &[(f.company_pda, c, 1), (f.pool_pda, p, 1), (f.user_pda, change, 1)],
    );
    let r = f.split(c, p, &v1);
    ok(&r, "execute_split_transfer");
    println!("execute_split_transfer (real cToken + Light, 3 outputs, prove-by-index): {} CU", r.compute_units_consumed);
    assert_eq!(f.next_leaf_index(), leaf + 4, "3 new leaves appended");
    let (company_leaf, pool_leaf, change_leaf) = (leaf + 1, leaf + 2, leaf + 3);

    // Effect 1: the input leaf is spent — a second spend fails.
    err(&f.split(c, p, &v1), "double spend of the input leaf");

    // Effect 2: the company leaf holds exactly `c` for the company PDA.
    let lie = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(c + 1, company_leaf)], &[(f.user_pda, c + 1, 1)],
    );
    err(&f.company_to_user_new(c + 1, "zupy:v1:ztransaction:36", &lie), "company leaf with a wrong amount");
    let spend_company = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(c, company_leaf)], &[(f.user_pda, c, 1)],
    );
    ok(&f.company_to_user_new(c, "zupy:v1:ztransaction:36", &spend_company), "company spends its leaf (exact amount)");

    // Effect 3: the pool leaf holds exactly `p` for the incentive pool PDA.
    err(&f.pool_self_transfer(p + 1, pool_leaf), "pool leaf with a wrong amount");
    ok(&f.pool_self_transfer(p, pool_leaf), "pool spends its leaf (exact amount)");

    // Effect 4: the change leaf is the user's — spend it user → company.
    let u2c = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(change, change_leaf)],
        &[(f.company_pda, 100_000_000, 1), (f.user_pda, 60_000_000, 1)],
    );
    let r = f.user_to_company(100_000_000, &u2c);
    ok(&r, "transfer_user_to_company from the change leaf");
    println!("transfer_user_to_company (real cToken + Light, 2 outputs): {} CU", r.compute_units_consumed);
}

/// taxa_pool = 0: no pool output at all.
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn split_with_zero_pool_has_no_pool_leaf() {
    let f = fork();
    let leaf = f.mint_leaf(&f.user_pda, 500_000_000);
    let v1 = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(500_000_000, leaf)],
        &[(f.company_pda, 500_000_000, 1)],
    );
    ok(&f.split(500_000_000, 0, &v1), "split with pool 0 spending the whole leaf");
    assert_eq!(f.next_leaf_index(), leaf + 2, "exactly one new leaf (company)");
    let spend = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(500_000_000, leaf + 1)], &[(f.user_pda, 500_000_000, 1)],
    );
    ok(&f.company_to_user_new(500_000_000, "zupy:v1:ztransaction:36", &spend), "company spends the whole-leaf output");
}

/// The legacy (396df04 / 3.17 adapter) payload fails closed before any CPI,
/// and a payload that lies about the leaf amount is refused by the real
/// cToken/Light (the program's leg check is not the only guard).
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn failure_modes_with_real_ctoken() {
    let f = fork();
    let leaf = f.mint_leaf(&f.user_pda, 1_000_000_000);

    // Header only (what the backend sends today) → InvalidInstructionData, nothing moves.
    let r = f.split(800_000_000, 40_000_000, &[]);
    assert_eq!(r.raw_result, Err(solana_instruction::error::InstructionError::InvalidInstructionData));

    // Leaf smaller than the legs → InsufficientBalance (6004) before the CPI.
    let short = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(500_000_000, leaf)],
        &[(f.company_pda, 800_000_000, 1), (f.pool_pda, 40_000_000, 1)],
    );
    assert_ix_custom_err(&f.split(800_000_000, 40_000_000, &short), 6004);

    // Declaring a bigger leaf than the real one: legs + change add up, the
    // program passes it, and the real cToken/Light reject it (hash mismatch).
    let inflated = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(2_000_000_000, leaf)],
        &[(f.company_pda, 800_000_000, 1), (f.pool_pda, 40_000_000, 1), (f.user_pda, 1_160_000_000, 1)],
    );
    err(&f.split(800_000_000, 40_000_000, &inflated), "inflated input leaf");

    // Overflow in the declared legs → SplitCalculationError (6029).
    assert_ix_custom_err(&f.split(u64::MAX, 1, &short), 6029);

    // The leaf is still intact after all the failures: a correct split works.
    let good = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(1_000_000_000, leaf)],
        &[(f.company_pda, 800_000_000, 1), (f.pool_pda, 40_000_000, 1), (f.user_pda, 160_000_000, 1)],
    );
    ok(&f.split(800_000_000, 40_000_000, &good), "split after the rejected attempts");
}

// ── Story 3.40 — consolidate_leaves ─────────────────────────────────────────

/// N user leaves → ONE user leaf with the exact sum (N = 2, 4, 8), against the
/// real cToken/Light. Effect: the merged leaf is spendable by the user with the
/// sum (and not with sum + 1); the input leaves cannot be spent again.
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn consolidate_user_leaves_2_4_8_with_real_ctoken() {
    for n in [2usize, 4, 8] {
        let f = fork();
        let amounts: Vec<u64> = (1..=n as u64).map(|i| i * 1_000_000 + 7).collect();
        let total: u64 = amounts.iter().sum();
        let inputs = f.mint_leaves(&f.user_pda, &amounts);
        let v1 = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.user_pda, total, 1)]);
        let before = f.next_leaf_index();
        let r = f.consolidate(OWNER_USER, total, &v1);
        ok(&r, "consolidate_leaves (user)");
        println!("consolidate_leaves user N={n} (real cToken + Light, prove-by-index): {} CU", r.compute_units_consumed);
        assert_eq!(f.next_leaf_index(), before + 1, "exactly ONE new leaf");
        let merged = before;

        // The inputs are spent: the same consolidation cannot run twice.
        err(&f.consolidate(OWNER_USER, total, &v1), "double spend of the consolidated inputs");

        // The merged leaf holds exactly `total` for the user PDA.
        let lie = build_v1_transfer(&zupy_mint(), None, &[Fork::input(total + 1, merged)], &[(f.company_pda, total + 1, 1)]);
        err(&f.user_to_company(total + 1, &lie), "merged leaf with a wrong amount");
        let spend = build_v1_transfer(&zupy_mint(), None, &[Fork::input(total, merged)], &[(f.company_pda, total, 1)]);
        ok(&f.user_to_company(total, &spend), "user spends the merged leaf (exact sum)");
    }
}

/// Company leaves → ONE company leaf; then the store pays a reward from it
/// through the hardened transfer_company_to_user (new layout, with memo).
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn consolidate_company_leaves_then_reward_with_real_ctoken() {
    let f = fork();
    let amounts = [3_000_000u64, 2_000_000, 1_000_000, 500_000];
    let total: u64 = amounts.iter().sum();
    let inputs = f.mint_leaves(&f.company_pda, &amounts);
    let v1 = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.company_pda, total, 1)]);
    let merged = f.next_leaf_index();
    let r = f.consolidate(OWNER_COMPANY, total, &v1);
    ok(&r, "consolidate_leaves (company, 4 leaves)");
    println!("consolidate_leaves company N=4: {} CU", r.compute_units_consumed);

    // A reward bigger than any single original leaf, paid from the merged one.
    let reward = 5_000_000u64;
    let pay = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(total, merged)],
        &[(f.user_pda, reward, 1), (f.company_pda, total - reward, 1)],
    );
    let r = f.company_to_user_new(reward, "zupy:v1:ztransaction:340", &pay);
    ok(&r, "transfer_company_to_user (new layout) from the merged leaf");
    println!("transfer_company_to_user new layout (real cToken + Light, 2 outputs): {} CU", r.compute_units_consumed);
    let (user_leaf, change_leaf) = (merged + 1, merged + 2);

    // Effect: the user leaf is the user's (exact), the change is the company's (exact).
    let u = build_v1_transfer(&zupy_mint(), None, &[Fork::input(reward, user_leaf)], &[(f.company_pda, reward, 1)]);
    ok(&f.user_to_company(reward, &u), "user spends the reward leaf");
    let c = build_v1_transfer(&zupy_mint(), None, &[Fork::input(total - reward, change_leaf)], &[(f.user_pda, total - reward, 1)]);
    ok(&f.company_to_user_new(total - reward, "zupy:v1:ztransaction:36", &c), "company spends its change leaf");
}

/// What the program refuses before the CPI, and what the real cToken refuses
/// after it (leaves of another owner, an inflated leaf).
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn consolidate_failure_modes_with_real_ctoken() {
    let f = fork();
    let inputs = f.mint_leaves(&f.user_pda, &[1_000_000, 2_000_000]);
    let total = 3_000_000u64;

    // Output to another owner → InvalidPDA (6007).
    let v = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.company_pda, total, 1)]);
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total, &v), 6007);
    // Output different from the declared amount → InvalidAmount (6005).
    let v = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.user_pda, total, 1)]);
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total - 1, &v), 6005);
    // Extra output (even to the owner) → InvalidInstructionData.
    let v = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.user_pda, 2_000_000, 1), (f.user_pda, 1_000_000, 1)]);
    assert_eq!(f.consolidate(OWNER_USER, 2_000_000, &v).raw_result, Err(solana_instruction::error::InstructionError::InvalidInstructionData));
    // Wrong mint → InvalidMint (6011).
    let v = build_v1_transfer(&Pubkey::new_unique(), None, &inputs, &[(f.user_pda, total, 1)]);
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total, &v), 6011);
    // Sum of inputs above the output (a burn) → SplitCalculationError (6029).
    let v = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.user_pda, total - 1, 1)]);
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total - 1, &v), 6029);

    // Leaves of ANOTHER owner (the company's), consolidated as the user: the
    // payload is consistent, the program signs only for the user PDA, and the
    // real cToken/Light reject it — the leaf hash commits to its owner.
    let foreign = f.mint_leaves(&f.company_pda, &[1_000_000, 2_000_000]);
    let v = build_v1_transfer(&zupy_mint(), None, &foreign, &[(f.user_pda, total, 1)]);
    // 14307 = InclusionProofByIndexFailed, raised inside account compression.
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total, &v), 14307);

    // Inflated input leaf: consistent payload, rejected by the real cToken/Light.
    let mut inflated = inputs.clone();
    inflated[0].amount += 1;
    let v = build_v1_transfer(&zupy_mint(), None, &inflated, &[(f.user_pda, total + 1, 1)]);
    assert_ix_custom_err(&f.consolidate(OWNER_USER, total + 1, &v), 14307);

    // After all the refusals the user's leaves are intact: the right consolidation works.
    let v = build_v1_transfer(&zupy_mint(), None, &inputs, &[(f.user_pda, total, 1)]);
    ok(&f.consolidate(OWNER_USER, total, &v), "consolidation after the rejected attempts");
}

// ── Story 3.40 — transfer_company_to_user hardened ──────────────────────────

/// Both layouts pay the user with the real cToken; the payloads a compromised
/// backend could send (change to a third party, a burn, a lie about the amount,
/// a bad memo) are refused BEFORE the CPI.
#[test]
#[ignore = "needs scripts/fetch-mainnet-fixtures.sh + mainnet build"]
fn company_to_user_hardened_with_real_ctoken() {
    let f = fork();
    let leaf = f.mint_leaf(&f.company_pda, 10_000_000);
    let good = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(10_000_000, leaf)],
        &[(f.user_pda, 4_000_000, 1), (f.company_pda, 6_000_000, 1)],
    );
    let thief = Pubkey::new_unique();
    let steal = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(10_000_000, leaf)],
        &[(f.user_pda, 4_000_000, 1), (thief, 6_000_000, 1)],
    );
    let burn = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(10_000_000, leaf)], &[(f.user_pda, 4_000_000, 1)],
    );

    // Refused before the CPI.
    assert_ix_custom_err(&f.company_to_user_new(4_000_000, "zupy:v1:ztransaction:1", &steal), 6007);
    assert_ix_custom_err(&f.company_to_user_new(4_000_000, "zupy:v1:ztransaction:1", &burn), 6029);
    // Story 36.6: the legacy layout is refused outright, even with a valid payload.
    assert_eq!(
        f.company_to_user_legacy(&good).raw_result,
        Err(solana_instruction::error::InstructionError::InvalidInstructionData),
    );
    assert_ix_custom_err(&f.company_to_user_new(3_000_000, "zupy:v1:ztransaction:1", &good), 6005);
    assert_ix_custom_err(&f.company_to_user_new(4_000_000, "ztransaction-1", &good), 6009);
    assert_eq!(
        f.company_to_user_new(4_000_000, "zupy:v1:ztransaction:1", &[]).raw_result,
        Err(solana_instruction::error::InstructionError::InvalidInstructionData),
    );

    // The leaf is intact after the refusals: the new layout pays the user.
    let r = f.company_to_user_new(4_000_000, "zupy:v1:ztransaction:1", &good);
    ok(&r, "transfer_company_to_user new layout");
    let (user_leaf, change_leaf) = (leaf + 1, leaf + 2);
    let u = build_v1_transfer(&zupy_mint(), None, &[Fork::input(4_000_000, user_leaf)], &[(f.company_pda, 4_000_000, 1)]);
    ok(&f.user_to_company(4_000_000, &u), "user spends the reward leaf (exact)");

    // And the change leaf pays a second reward (the legacy layout of the same
    // payment is refused first, leaving the leaf intact).
    let second = build_v1_transfer(
        &zupy_mint(), None, &[Fork::input(6_000_000, change_leaf)],
        &[(f.user_pda, 1_000_000, 1), (f.company_pda, 5_000_000, 1)],
    );
    assert_eq!(
        f.company_to_user_legacy(&second).raw_result,
        Err(solana_instruction::error::InstructionError::InvalidInstructionData),
    );
    let r = f.company_to_user_new(1_000_000, "zupy:v1:ztransaction:2", &second);
    ok(&r, "transfer_company_to_user from the change leaf");
    println!("transfer_company_to_user second reward (real cToken + Light, 2 outputs): {} CU", r.compute_units_consumed);
}

/// Regression on REAL traffic (story 3.40, rewritten for the single layout in
/// story 36.6): every recent successful mainnet `transfer_company_to_user` —
/// `36-6-evidence/c2u_real_payloads_v2.py.txt` writes the fixture — passes the
/// checks of the current layout: not the removed legacy shape, PDAs/bumps derive
/// from the header, memo format, output 0 = user PDA with exactly the header
/// amount, CPI authority = company PDA, full payload validation.
#[test]
#[ignore = "needs tests/fixtures/mainnet/c2u_recent_v2.txt (36-6-evidence/c2u_real_payloads_v2.py.txt)"]
fn real_mainnet_company_to_user_payloads_pass_the_hardened_validator() {
    use pinocchio::Address;
    use zupy_token_program::helpers::memo::validate_memo_format;
    use zupy_token_program::helpers::v1_transfer::{v1_first_output, validate_v1_transfer_payload, V1Leg};

    let text = std::fs::read_to_string(fixtures().join("c2u_recent_v2.txt")).expect("run c2u_real_payloads_v2.py.txt");
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let data: Vec<u8> = (0..f[0].len()).step_by(2).map(|i| u8::from_str_radix(&f[0][i..i + 2], 16).unwrap()).collect();
        let (mint, company, user, cpi_authority) = (pk(f[1]), pk(f[2]), pk(f[3]), pk(f[4]));
        assert_eq!(&data[..8], &DISC_C2U);
        let body = &data[8..];
        assert_ne!(&body[18..26], &V1_TRANSFER_DISC, "{}: removed legacy layout", f[5]);

        let company_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let user_id = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let amount = u64::from_le_bytes(body[16..24].try_into().unwrap());
        assert_eq!(derive_company_pda(company_id), (company, body[24]), "{}: company PDA", f[5]);
        assert_eq!(derive_user_pda(user_id), (user, body[25]), "{}: user PDA", f[5]);
        assert_eq!(cpi_authority, company, "{}: CPI authority = company PDA", f[5]);

        let memo_len = u32::from_le_bytes(body[26..30].try_into().unwrap()) as usize;
        let memo = core::str::from_utf8(&body[30..30 + memo_len]).unwrap();
        assert_eq!(validate_memo_format(memo), Ok(()), "{}: memo {memo}", f[5]);

        let v1 = &body[30 + memo_len..];
        let (owner, first) = v1_first_output(v1).unwrap();
        assert_eq!(owner, user.as_ref(), "{}: output 0 is the user", f[5]);
        assert!(amount > 0);
        assert_eq!(first, amount, "{}: output 0 = header amount", f[5]);
        let (mint_a, company_a, user_a) =
            (Address::from(mint.to_bytes()), Address::from(company.to_bytes()), Address::from(user.to_bytes()));
        let legs = [V1Leg { owner: &user_a, amount }];
        assert_eq!(validate_v1_transfer_payload(v1, &mint_a, &company_a, &legs), Ok(()), "{}", f[5]);
        n += 1;
    }
    println!("{n} real mainnet transfer_company_to_user payloads pass the hardened validator");
    assert!(n >= 20, "too few payloads: {n}");
}
