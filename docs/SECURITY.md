# SECURITY.md

## Security Policy

This document describes the **current** security posture of `pq_drse_lib` `v0.3.0`.

## Current Security Status

`pq_drse_lib` `v0.3.0` is **not a complete working implementation** of its intended cryptographic workflow.

The crate currently compiles, but the receiver-key generation path for the intended HPKE configuration returns `Hpke("InvalidConfig")` in the present implementation path.

Therefore:

- the intended receiver-bound cryptographic workflow is not fully operational,
- end-to-end verification is not currently available as a normal passing test path,
- this crate should not be treated as production-ready for the intended ML-KEM-768 receiver bundle flow.

## Supported Versions

| Version | Status |
|---|---|
| 0.3.x | Prototype / broken receiver-key path |
| < 0.3.0 | Not supported |

## Security Boundaries

This project is an application-layer cryptographic integration library.
It is **not** itself a compliance boundary, certification boundary, or complete cryptographic assurance boundary.

Its security properties depend on:

- the correctness of the selected HPKE implementation,
- the correctness of the selected provider,
- key management,
- trust distribution of sender public keys,
- secure handling of receiver private keys,
- safe build/release processes,
- secure host/runtime configuration.

## Known Security Limitations

### 1. Broken receiver-key generation path

The current implementation cannot be relied upon for the intended receiver key generation flow.

### 2. No complete validated end-to-end workflow

The intended bundle-generation and verification flow is not currently validated as a passing test path.

### 3. Prototype state

This version should be treated as prototype code until the HPKE configuration issue is repaired and the end-to-end tests are re-enabled and passing.

## Safe Usage Guidance

Until repaired:

- do not present this crate as a complete working ML-KEM-768 receiver-bound implementation,
- do not rely on ignored tests as proof of cryptographic correctness,
- do not assume successful portability of the intended receiver workflow,
- do not use this version as a sole assurance mechanism for high-trust production systems.

## Dependency Posture

The crate currently relies on a combination intended to use:

- `hpke-rs`
- RustCrypto provider
- `KemAlgorithm::MlKem768`
- `ML-DSA-65`
- `SHAKE256`
- `HMAC-SHA256`

However, the current runtime behavior indicates the receiver-key generation path is not functioning in the present implementation.

## Key Handling Guidance

If receiver private key material is used during repair or integration testing:

- keep it outside general metadata files unless the design explicitly requires otherwise,
- protect it with the narrowest practical access controls,
- avoid long-lived plaintext exposure in logs, CI output, or artifacts,
- treat test fixture keys as non-production-only material.

## Testing Guidance

The current test posture is intentionally conservative:

- digest behavior is actively checked,
- the known invalid-config path is explicitly checked,
- true end-to-end verification remains ignored until repair.

See `TEST.md` for operational details.

## Reporting a Vulnerability

If you discover a security issue in this project:

1. do not publish exploit details in a public issue first,
2. include the affected version,
3. include whether the issue concerns:
   - receiver-key generation,
   - bundle verification,
   - signature verification,
   - digest / tag mismatch behavior,
   - key handling,
   - unsafe serialization,
   - dependency/provider behavior,
4. include a minimal reproduction where possible.

## Required Exit Criteria Before Production Use

Before this crate should be considered for production-style use, all of the following should be true:

- receiver-key generation succeeds,
- bundle generation succeeds,
- end-to-end verification succeeds,
- ignored workflow tests are re-enabled and pass,
- documentation reflects actual behavior,
- security guidance is revised to match the repaired code path.
