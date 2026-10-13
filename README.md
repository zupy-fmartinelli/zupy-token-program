# ZUPY Token Program

Solana program for the ZUPY token ecosystem, built with the [Pinocchio](https://github.com/anza-xyz/pinocchio) zero-copy framework.

## Addresses

| | Address |
|---|---------|
| **Program ID** | `ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU` |
| **Mint** | `ZUPYxKLjfRyRmoF6j8Su8D3aTDkB4k4uqXLqHn8wcao` |

## Features

- Zero-copy account deserialization (no heap allocations)
- Token-2022 (SPL Token Extensions) integration
- ZK compressed tokens via [Light Protocol](https://www.lightprotocol.com/)
- Three-wallet security architecture (Treasury, Mint Authority, Transfer Authority)
- Rate limiting (per-transaction and daily)
- On-chain metadata (Token Metadata Interface)

## Build

Requires [Solana CLI](https://docs.anza.xyz/cli/install) and the SBF toolchain.

```bash
# Mainnet build. The default feature is `devnet`: a plain `cargo build-sbf`
# produces a binary with devnet settings, which must never go to mainnet.
cargo build-sbf --no-default-features --features mainnet

# Unit tests
cargo test --lib

# Full test suite (requires the SBF binary)
SBF_OUT_DIR=target/deploy cargo test
```

## Verify Build

The deployed program is a deterministic build of this repository, verified with
[solana-verify](https://github.com/Ellipsis-Labs/solana-verifiable-build) and registered with OtterSec
(status: `https://verify.osec.io/status/ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU`).
To reproduce it yourself (Docker required):

```bash
solana-verify build --base-image solanafoundation/solana-verifiable-build:3.0.13 \
    --library-name zupy_token_program -- --no-default-features --features mainnet
solana-verify get-executable-hash target/deploy/zupy_token_program.so
solana-verify get-program-hash -u https://api.mainnet-beta.solana.com ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU
```

Both hashes must match.

The program interface (Codama IDL) is published on-chain as the program's canonical metadata
([`idl/`](idl/)), so explorers decode its instructions by name.

## Architecture

```
src/
  lib.rs              Entrypoint + instruction dispatch
  constants.rs        Seeds, program IDs, authority pubkeys
  error.rs            Error codes
  instructions/       One file per instruction handler
  helpers/            Shared validation, PDA derivation, CPI wrappers
  state/              Zero-copy account layouts (TokenState, RateLimitState)
tests/
  test_transfers.rs       Full integration tests (Mollusk SVM)
  test_split_burns.rs     Split transfer + burn edge cases
  test_cu_benchmarks.rs   Compute unit benchmarks (all instructions)
  test_entrypoint.rs      Dispatch + discriminator tests
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
