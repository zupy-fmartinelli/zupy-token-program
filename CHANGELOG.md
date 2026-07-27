# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [1.3.0](https://github.com/zupy-fmartinelli/zupy-token-program/compare/v1.2.0...v1.3.0) (2026-07-03)


### Features

* **split:** burn-free explicit-amount execute_split_transfer (AD-A1) ([dd1f3df](https://github.com/zupy-fmartinelli/zupy-token-program/commit/dd1f3df66ab46711c360356b0658af951dd16d24))


### Code Refactoring

* **dedup:** extract push_remaining_metas + validate_transfer_common_1_8 ([ca11553](https://github.com/zupy-fmartinelli/zupy-token-program/commit/ca1155364311e327f64c66019da42fd8f87d560e))
* **dedup:** zero all remaining duplication (2.6% -> 0.0%) ([1377b21](https://github.com/zupy-fmartinelli/zupy-token-program/commit/1377b217cdf9b84f511b36f7adf4dc13808b8d47))
* **sonar:** clear 3 pre-existing violations (S107 x2, S3776) ([81e2c85](https://github.com/zupy-fmartinelli/zupy-token-program/commit/81e2c853aa495fd078e4bc755a01972820ef6eb5))
* **sonar:** finish S3776 — extract report + cold-path builder (cc 18->under 15) ([2e4873f](https://github.com/zupy-fmartinelli/zupy-token-program/commit/2e4873fda13ce56de305350a009200ee706c0186))

## [1.2.0](https://github.com/zupy-fmartinelli/zupy-token-program/compare/v1.1.0...v1.2.0) (2026-02-28)


### Features

* add logo field to security_txt for Solana Explorer display ([e22e9a9](https://github.com/zupy-fmartinelli/zupy-token-program/commit/e22e9a98dfd2c655fabc658365497359738bf013))


### Code Refactoring

* rename crate from zupy-pinocchio to zupy-token-program ([b97f80a](https://github.com/zupy-fmartinelli/zupy-token-program/commit/b97f80aa2cc8fb48b4da7d3d81d9a66b2bb06650))

## [1.1.0](https://github.com/zupy-fmartinelli/zupy-token-program/compare/v1.0.1...v1.1.0) (2026-02-28)


### Features

* embed security.txt in program binary ([4019234](https://github.com/zupy-fmartinelli/zupy-token-program/commit/4019234fb0ff189cf90486a20983b0e313893b3a))

## [1.0.1](https://github.com/zupy-fmartinelli/zupy-token-program/compare/v1.0.0...v1.0.1) (2026-02-28)


### Code Refactoring

* extract shared return-to-pool helpers to eliminate duplication ([578f6cb](https://github.com/zupy-fmartinelli/zupy-token-program/commit/578f6cb4d9b43538fc83348832cda603d436eaa7))
