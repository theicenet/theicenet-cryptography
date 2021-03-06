# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - TBC

### Added

- Generic service for cryptographically secure random data generation (which replaces the specific ones for IV & Salt generation) [@jjfidalgo]
- Multiple beans for the AES cipher for different block modes of operation can be injected in the same Spring Boot context [@jjfidalgo]
- Multiple beans for the RSA cipher for different paddings can be injected in the same Spring Boot context [@jjfidalgo]
- Multiple beans for the RSA signer for different algorithms can be injected in the same Spring Boot context [@jjfidalgo]
- Multiple beans for the DSA signer for different algorithms can be injected in the same Spring Boot context [@jjfidalgo]
- Multiple beans for the ECDSA key generator for different EC curves can be injected in the same Spring Boot context [@jjfidalgo]

### Changed

- Specific services for IV & Salt generation has been replaced by a single generic service for secure random data generation [@jjfidalgo]

### Deprecated

### Removed

- Service for IV generation (replaced by the generic SecureRandomDataService) (no previous deprecation) [@jjfidalgo]
- Service for Salt generation (replaced by the generic SecureRandomDataService) (no previous deprecation) [@jjfidalgo]

### Fixed

### Security

## [1.0.3] - 2021‑01‑24

### Added

- CHANGELOG.md [@jjfidalgo]

### Changed

- Upgrade library dependencies to their latest versions [@jjfidalgo]


## [1.0.2] - 2020‑10‑18

### Changed

- Upgrade library dependencies to their latest versions [@jjfidalgo]

## [1.0.1] - 2020‑04‑15

### Fixed

- Issue it doesn't release parent pom to Maven's Central [@jjfidalgo]

## [1.0.0] - 2020‑04‑15

### Added

- Symmetric cryptography key generation for AES algorithm [@jjfidalgo]
- Symmetric cryptography encrypt/decrypt for AES algorithm with Block Modes of Operation ECB (non IV based), CBC, CFB, OFB, CTR (IV based) [@jjfidalgo]
- Symmetric cryptography MAC generation for HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512 algorithms [@jjfidalgo]
- Asymmetric cryptography key generation for RSA, RSA, ECDSA, ECDH algorithms [@jjfidalgo]
- Asymmetric cryptography key agreement for ECDH algorithm [@jjfidalgo]
- Asymmetric cryptography encrypt/decrypt for RSA algorithm [@jjfidalgo]
- Asymmetric cryptography signature generation/verification for RSA, DSA, ECDSA algorithms [@jjfidalgo]
- Hashing generation for MD5, SHA_1, SHA_224, SHA_256, SHA_384, SHA_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512, Whirlpool, Tiger, SM3 algorithms [@jjfidalgo]
- Password based key derivation for PBKDF2 (PBKDF2WithHmac - SHA1, SHA256, SHA512, SHA3_256, SHA3_512), Scrypt, Argon2 (ARGON2_D, ARGON2_I, ARGON2_ID, ARGON2_VERSION_10, ARGON2_VERSION_13) algorithms [@jjfidalgo]
- Random data generation for Initialization Vector (IV) and Salt [@jjfidalgo]
- Bitbucket pipeline with the CI & release process to Maven's Central [@jjfidalgo]

[unreleased]: https://github.com/theicenet/theicenet-cryptography/compare/theicenet-cryptography-1.1.0...HEAD
[1.1.0]: https://github.com/theicenet/theicenet-cryptography/compare/theicenet-cryptography-1.0.3...theicenet-cryptography-1.1.0
[1.0.3]: https://github.com/theicenet/theicenet-cryptography/compare/theicenet-cryptography-1.0.2...theicenet-cryptography-1.0.3
[1.0.2]: https://github.com/theicenet/theicenet-cryptography/compare/theicenet-cryptography-1.0.1...theicenet-cryptography-1.0.2
[1.0.1]: https://github.com/theicenet/theicenet-cryptography/compare/theicenet-cryptography-1.0.0...theicenet-cryptography-1.0.1
[1.0.0]: https://github.com/theicenet/theicenet-cryptography/releases/tag/theicenet-cryptography-1.0.0
[@jjfidalgo]: https://github.com/jjfidalgo