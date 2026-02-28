# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the ZUPY Token Program, please report it responsibly.

**Email:** security@zupy.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Scope

This policy covers the on-chain Solana program source code in this repository.

## Security Architecture

- **Treasury:** Hardware wallet (cold storage)
- **Mint Authority:** HSM-backed signing
- **Transfer Authority:** HSM-backed signing
- **Upgrade Authority:** Hardware wallet (multisig planned)
- **Overflow checks:** Enabled in release builds for financial safety
- **Rate limiting:** Per-transaction and daily limits enforced on-chain
