# pq_drse_lib

`pq_drse_lib` is a Rust 2024 library intended to provide a post-quantum, receiver-bound verification bundle using:

- `hpke-rs`
- the RustCrypto provider
- `KemAlgorithm::MlKem768`
- `ML-DSA-65`
- `SHAKE256`
- `HMAC-SHA256`

## Current Status (v0.3.0)

**This crate currently compiles, but the intended ML-KEM-768 + `hpke-rs` RustCrypto receiver-key generation path is not working in the current implementation.**

Observed current behavior:

- the crate builds successfully,
- the SHAKE256 digest helper works,
- `generate_receiver_key_file()` currently returns `Hpke("InvalidConfig")`,
- tests that depend on successful receiver key generation are presently ignored.

As a result, the current `v0.3.0` tree should be treated as a **design/prototype snapshot**, not a complete working designated-recipient bundle implementation.

## What Works Today

### 1. Digest helper

The file-digest helper based on SHAKE256 is present and testable.

### 2. Library compilation

The crate builds and the library/test harness can be executed.

### 3. Failure-state regression coverage

The current test suite captures the present failure mode of receiver key generation so CI can distinguish between:

- a digest/helper regression, and
- the known HPKE configuration failure.

## What Does Not Work Today

### Receiver key generation

`generate_receiver_key_file()` is currently expected to fail with `Hpke("InvalidConfig")`.

### Bundle-generation workflow

The intended end-to-end path:

1. generate receiver key material,
2. produce a bundle,
3. verify the bundle with the matching receiver private key,

is **not currently operational** under the present `hpke-rs` + RustCrypto + `MlKem768` implementation path.

## Current Project Layout

- `src/lib.rs`
- `src/bin/keygen.rs`
- `src/bin/producer.rs`
- `src/bin/consumer.rs`
- `tests/test_suite.rs`
- `SECURITY.md`
- `TEST.md`

## Test Posture

The test suite is currently organized so that:

- digest behavior remains actively verified,
- the current HPKE receiver-key failure is explicitly checked,
- end-to-end workflow tests remain ignored until the HPKE configuration path is repaired.

See `TEST.md` for details.

## Intended Cryptographic Shape

The intended design is still:

- receiver-bound encapsulation with ML-KEM-768,
- sender authenticity with ML-DSA-65,
- SHAKE256 file digesting,
- HMAC-SHA256 receiver tag over the digest.

However, the HPKE implementation path currently blocks that intended flow.

## Practical Guidance

Treat this crate as one of the following until repaired:

1. a prototype,
2. a regression-tracking branch,
3. a documentation scaffold for a later working implementation.

Do **not** treat `v0.3.0` as a complete production-ready implementation of the intended receiver-bound post-quantum verification design.

## Suggested Next Remediation Steps

1. Revalidate the exact `hpke-rs` provider / KEM combination against the runtime actually in use.
2. Confirm whether bare `MlKem768` is operational in the selected provider path.
3. If strict ML-KEM-768 remains required and the current `hpke-rs` path cannot be made functional, replace the HPKE implementation path with one that demonstrably supports the required ML-KEM-768 workflow.
4. Re-enable end-to-end tests only after successful receiver-key generation and bundle verification are working.

## Version Statement

This README describes the **current observed v0.3.0 behavior**, not the originally intended architecture claims.
