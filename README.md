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

Requires [Solana CLI](https://docs.solanalabs.com/cli/install) and the SBF toolchain.

```bash
# Build for deployment
cargo build-sbf

# Unit tests
cargo test --lib

# Full test suite (requires SBF binary)
cargo build-sbf && cargo test
```

## Verify Build

This program is verified on [Solana Explorer](https://explorer.solana.com/). To verify locally:

```bash
solana-verify get-program-hash ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU
solana-verify get-executable-hash target/deploy/zupy_pinocchio.so
```

Both hashes must match.

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
