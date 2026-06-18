use pq_drse_lib::{
    Bundle, ReceiverKeyFile, file_digest, generate_receiver_key_file, generate_sender_key_file,
    produce_bundle, verify_bundle,
};
use std::fs;

#[test]
fn shake256_digest_is_stable_and_32_bytes() {
    let file = b"important enterprise object payload";
    let d1 = file_digest(file);
    let d2 = file_digest(file);

    assert_eq!(d1, d2);
    assert_eq!(d1.len(), 32);
}

#[test]
fn bundle_json_round_trip() {
    let sender = generate_sender_key_file().expect("sender keygen should succeed");
    let receiver = generate_receiver_key_file().expect("receiver keygen should succeed");
    let file = b"important enterprise object payload";

    let bundle = produce_bundle(
        file,
        &sender,
        &receiver,
        Some("json-round-trip-mlkem-shake256"),
    )
    .expect("produce_bundle should succeed");

    let json = bundle.to_json_pretty().expect("json export must succeed");
    let reparsed = Bundle::from_json_str(&json).expect("json import must succeed");

    assert_eq!(bundle, reparsed);
}

#[test]
fn produce_bundle_populates_expected_fields() {
    let sender = generate_sender_key_file().expect("sender keygen should succeed");
    let receiver = generate_receiver_key_file().expect("receiver keygen should succeed");
    let file = b"important enterprise object payload";

    let bundle = produce_bundle(file, &sender, &receiver, Some("field-check-mlkem-shake256"))
        .expect("produce_bundle should succeed");

    assert_eq!(bundle.version, 3);
    assert_eq!(bundle.context, "field-check-mlkem-shake256");
    assert_eq!(bundle.file_digest.len(), 32);
    assert!(!bundle.receiver_tag.is_empty());
    assert!(!bundle.hpke_enc.is_empty());
    assert!(!bundle.hpke_ct.is_empty());
    assert!(!bundle.sender_public_key.is_empty());
    assert!(!bundle.sender_signature.is_empty());
}

#[test]
fn receiver_key_file_matches_latest_shape() {
    let receiver = generate_receiver_key_file().expect("receiver keygen should succeed");

    assert_eq!(receiver.algorithm, "hpke-rs 0.6.x");
    assert_eq!(receiver.hpke_provider, "hpke-rs-rust-crypto");
    assert_eq!(receiver.hpke_kem, "MlKem768");
    assert!(!receiver.public_key_b64.is_empty());
}

#[test]
#[ignore = "requires external receiver private key fixture; latest ReceiverKeyFile intentionally contains only the public key"]
fn end_to_end_verify_bundle_with_external_receiver_private_key() {
    let receiver_keys_json = std::env::var("TEST_RECEIVER_KEYS_JSON")
        .expect("set TEST_RECEIVER_KEYS_JSON to a receiver_keys.json path");
    let receiver_private_key_b64_path = std::env::var("TEST_RECEIVER_PRIVATE_KEY_B64")
        .expect("set TEST_RECEIVER_PRIVATE_KEY_B64 to a file containing the matching receiver private key base64");

    let receiver: ReceiverKeyFile = serde_json::from_slice(
        &fs::read(&receiver_keys_json).expect("receiver keys file should be readable"),
    )
    .expect("receiver keys json should parse");

    let receiver_private_key_b64 = fs::read_to_string(&receiver_private_key_b64_path)
        .expect("receiver private key file should be readable");

    let sender = generate_sender_key_file().expect("sender keygen should succeed");
    let file = b"important enterprise object payload";

    let bundle = produce_bundle(
        file,
        &sender,
        &receiver,
        Some("verify-round-trip-mlkem-shake256"),
    )
    .expect("produce_bundle should succeed");

    let verdict = verify_bundle(
        file,
        &sender.public_key_b64,
        receiver_private_key_b64.trim(),
        &bundle,
    )
    .expect("verify_bundle should succeed with the matching receiver private key");

    assert!(verdict.file_digest_valid);
    assert!(verdict.receiver_tag_valid);
    assert!(verdict.sender_signature_valid);
}
