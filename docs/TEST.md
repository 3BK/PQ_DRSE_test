# TEST.md

## Test Strategy for `pq_drse_lib` v0.3.0

This document describes the **current** testing posture.

## Summary

The crate's current tests are designed to reflect the present code state.

At this time:

- SHAKE256 digest behavior is tested,
- the known receiver-key generation failure is tested,
- end-to-end workflow tests remain ignored because the intended HPKE receiver-key path is not currently working.

## Current Expected Test Outcome

A normal targeted run such as:

```bash
cargo test --test test_suite --target x86_64-unknown-linux-musl
```

is currently expected to produce a result equivalent to:

- passing digest stability checks,
- passing failure-state regression checks,
- ignored end-to-end workflow tests.

## Why Some Tests Are Ignored

The ignored tests are ignored **because they depend on successful receiver-key generation**.

At present, `generate_receiver_key_file()` returns `Hpke("InvalidConfig")`, so tests that require a functioning receiver key generation path are intentionally not treated as normal pass/fail gating tests.

## Current Test Categories

### Active tests

#### `shake256_digest_is_stable_and_32_bytes`
Checks that the digest helper is deterministic and returns 32 bytes.

#### `receiver_keygen_currently_returns_invalid_config`
Confirms the current HPKE failure mode remains visible and explicit.

This protects CI from falsely implying the receiver-key path is working.

### Ignored tests

#### `bundle_json_round_trip`
Ignored because it depends on successful receiver key generation.

#### `produce_bundle_populates_expected_fields`
Ignored because it depends on successful receiver key generation.

#### `end_to_end_verify_bundle_with_external_receiver_private_key`
Ignored because it depends on both:

- successful receiver key generation, and
- an external receiver private key fixture.

## Interpretation of Test Results

### If the active tests pass
That means only:

- the digest helper still behaves as expected, and
- the crate still exhibits the known HPKE failure mode consistently.

It does **not** mean the full cryptographic workflow is working.

### If receiver-key generation unexpectedly starts succeeding
That is a signal to:

1. revise the tests,
2. re-enable the ignored workflow tests,
3. verify the implementation path end-to-end,
4. update README.md and SECURITY.md.

### If the failure mode changes
Then the failure-regression test should be updated to reflect the new observed behavior.

## Recommended Commands

### Run the integration test file
```bash
cargo test --test test_suite --target x86_64-unknown-linux-musl
```

### Run ignored tests explicitly
```bash
cargo test --test test_suite --target x86_64-unknown-linux-musl -- --ignored
```

Note: ignored tests are not expected to pass until the underlying HPKE configuration issue is repaired.

## Exit Criteria for Revising This Test Strategy

This test strategy should be revised when all of the following become true:

- receiver-key generation succeeds,
- bundle generation succeeds,
- end-to-end verification succeeds,
- ignored workflow tests can be re-enabled as normal tests.

At that point this document should be rewritten from a failure-state regression strategy to a normal functional verification strategy.
