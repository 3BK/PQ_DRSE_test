# PQ_DRSE_test - Post-Quantum Designated-Recipient Signed Encapsulation

`PQ_DRSE_test` is a Rust 2024 library that creates and verifies a **file-bound attestation bundle** with two independent assurances:

1. **Receiver validation** using `hpke-rs` with the **RustCrypto provider** and **ML-KEM-768**.
2. **Sender authenticity** using **ML-DSA-65** over a canonical transcript.


## Cryptographic profile

- **HPKE implementation:** `hpke-rs`
- **HPKE provider:** `hpke-rs-rust-crypto`
- **HPKE KEM:** `ML-KEM-768`
- **HPKE KDF:** `HKDF-SHA256`
- **HPKE AEAD:** `ChaCha20-Poly1305`
- **Sender signature:** `ML-DSA-65`
- **File digest / receiver tag input:** `SHAKE256`
- **Receiver tag:** `HMAC-SHA256(validation_secret, file_digest)`

## Project layout

- `Cargo.toml`
- `README.md`
- `SECURITY.md`
- `src/lib.rs`
- `src/bin/keygen.rs`
- `src/bin/producer.rs`
- `src/bin/consumer.rs`
- `tests/test_suite.rs`

## Example workflow

### 1. Generate keys

```bash
cargo run --bin keygen
```

### 2. Produce a bundle

```bash
cargo run --bin producer -- ./out/sender_keys.json ./out/receiver_keys.json ./README.md ./out/bundle.json
```

### 3. Consume / verify a bundle

```bash
cargo run --bin consumer -- ./out/receiver_keys.json ./out/bundle.json ./README.md
```
