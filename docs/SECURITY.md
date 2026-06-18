# SECURITY.md

## Security Policy

This project provides file-bound receiver validation and sender authenticity using:

- `hpke-rs` with the RustCrypto provider
- `KemAlgorithm::MlKem768`
- `ML-DSA-65`
- `SHAKE256`
- `HMAC-SHA256`
- `zeroize`

This document describes project security expectations, reporting guidance, and operational hardening guidance.

---

## Supported Versions

| Version | Status |
|---|---|
| 0.3.x | Supported |
| < 0.3.0 | Not supported |

---

## Security Boundaries

This project is an application-layer cryptographic integration library.
It is **not** a certification boundary and does not by itself establish compliance with any framework, standard, or regulation.

The effective security posture depends on:

- correct dependency pinning,
- correct key management,
- trusted sender public-key distribution,
- secure receiver private-key storage,
- secure build and release practices,
- correct logging and incident response practices,
- platform and runtime hardening.

---

## Key Requirements

- Do not downgrade below `hpke-rs` / `hpke-rs-rust-crypto` `0.6.0`.
- Protect sender ML-DSA signing material with the narrowest possible access controls.
- Protect receiver HPKE private keys as high-sensitivity secrets.
- Verify bundles only against trusted sender public keys from an authenticated trust channel.

---

## Reporting a Vulnerability

If you believe you have found a security issue in this project:

1. Do **not** open a public issue with exploit details.
2. Share a private report with:
   - affected version(s),
   - impact summary,
   - reproduction details,
   - proof-of-concept only where necessary,
   - recommended mitigation if known.
3. Allow reasonable time for triage and remediation before public disclosure.
