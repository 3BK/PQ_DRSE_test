#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use hpke_rs::{hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm}, Hpke, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use shake::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sha2::Sha256;
use std::fmt::Write as _;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VERSION: u8 = 3;
pub const HPKE_PROVIDER_NAME: &str = "hpke-rs-rust-crypto";
pub const HPKE_KEM_NAME: &str = "MlKem768";
pub const HPKE_KDF_NAME: &str = "HKDF-SHA256";
pub const HPKE_AEAD_NAME: &str = "ChaCha20Poly1305";
pub const CONTEXT_LABEL: &str = "pq-hpke-file-attest/mlkem/shake256/v3";
pub const VALIDATION_SECRET_LEN: usize = 32;
pub const FILE_DIGEST_LEN: usize = 32;

pub type HmacSha256 = Hmac<sha2::Sha256>;
pub type DefaultHpke = Hpke<HpkeRustCrypto>;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("failed to encode bundle as JSON: {0}")]
    JsonSerialize(#[from] serde_json::Error),
    #[error("failed to decode base64 field: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid sender public key encoding")]
    InvalidSenderPublicKey,
    #[error("invalid sender signature encoding")]
    InvalidSenderSignature,
    #[error("invalid sender seed length")]
    InvalidSenderSeedLength,
    #[error("bundle file digest does not match supplied file")]
    FileDigestMismatch,
    #[error("receiver tag does not match supplied file")]
    ReceiverTagMismatch,
    #[error("sender public key in bundle does not match the trusted sender key")]
    SenderPublicKeyMismatch,
    #[error("sender signature verification failed")]
    SignatureVerificationFailed,
    #[error("hpke operation failed: {0}")]
    Hpke(String),
    #[error("random generation failed")]
    RandomGeneration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleJson {
    pub version: u8,
    pub hpke_provider: String,
    pub hpke_kem: String,
    pub hpke_kdf: String,
    pub hpke_aead: String,
    pub file_digest_b64: String,
    pub receiver_tag_b64: String,
    pub hpke_enc_b64: String,
    pub hpke_ct_b64: String,
    pub sender_mldsa65_public_key_b64: String,
    pub sender_mldsa65_signature_b64: String,
    pub context: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub version: u8,
    pub file_digest: Vec<u8>,
    pub receiver_tag: Vec<u8>,
    pub hpke_enc: Vec<u8>,
    pub hpke_ct: Vec<u8>,
    pub sender_public_key: Vec<u8>,
    pub sender_signature: Vec<u8>,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderKeyFile {
    pub algorithm: String,
    pub public_key_b64: String,
    pub seed_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverKeyFile {
    pub algorithm: String,
    pub hpke_provider: String,
    pub hpke_kem: String,
    pub public_key_b64: String,
    pub private_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub file_digest_valid: bool,
    pub receiver_tag_valid: bool,
    pub sender_signature_valid: bool,
    pub file_digest_hex: String,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ProducerSecrets {
    pub sender_seed: [u8; 32],
    pub receiver_hpke_public_key: Vec<u8>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ConsumerSecrets {
    pub receiver_hpke_private_key: Vec<u8>,
}

impl Bundle {
    pub fn to_json_pretty(&self) -> Result<String, AttestError> {
        let json = BundleJson {
            version: self.version,
            hpke_provider: HPKE_PROVIDER_NAME.to_string(),
            hpke_kem: HPKE_KEM_NAME.to_string(),
            hpke_kdf: HPKE_KDF_NAME.to_string(),
            hpke_aead: HPKE_AEAD_NAME.to_string(),
            file_digest_b64: B64.encode(&self.file_digest),
            receiver_tag_b64: B64.encode(&self.receiver_tag),
            hpke_enc_b64: B64.encode(&self.hpke_enc),
            hpke_ct_b64: B64.encode(&self.hpke_ct),
            sender_mldsa65_public_key_b64: B64.encode(&self.sender_public_key),
            sender_mldsa65_signature_b64: B64.encode(&self.sender_signature),
            context: self.context.clone(),
        };
        Ok(serde_json::to_string_pretty(&json)?)
    }

    pub fn from_json_str(input: &str) -> Result<Self, AttestError> {
        let parsed: BundleJson = serde_json::from_str(input)?;
        Ok(Self {
            version: parsed.version,
            file_digest: B64.decode(parsed.file_digest_b64)?,
            receiver_tag: B64.decode(parsed.receiver_tag_b64)?,
            hpke_enc: B64.decode(parsed.hpke_enc_b64)?,
            hpke_ct: B64.decode(parsed.hpke_ct_b64)?,
            sender_public_key: B64.decode(parsed.sender_mldsa65_public_key_b64)?,
            sender_signature: B64.decode(parsed.sender_mldsa65_signature_b64)?,
            context: parsed.context,
        })
    }
}

pub fn generate_sender_key_file() -> Result<SenderKeyFile, AttestError> {
    let sk = SigningKey::<MlDsa65>::generate();
    let pk = sk.verifying_key();
    let seed = sk.to_seed();
    Ok(SenderKeyFile {
        algorithm: "ML-DSA-65".to_string(),
        public_key_b64: B64.encode(pk.encode()),
        seed_b64: B64.encode(seed),
    })
}

pub fn generate_receiver_key_file() -> Result<ReceiverKeyFile, AttestError> {
    let mut hpke = default_hpke();
    let kp = hpke.generate_key_pair().map_err(|e| AttestError::Hpke(format!("{e:?}")))?;
    let (sk, pk) = kp.into_keys();
    Ok(ReceiverKeyFile {
        algorithm: "hpke-rs 0.6.x".to_string(),
        hpke_provider: HPKE_PROVIDER_NAME.to_string(),
        hpke_kem: HPKE_KEM_NAME.to_string(),
        public_key_b64: B64.encode(pk.as_slice()),
        private_key_b64: B64.encode(sk.as_slice()),
    })
}

pub fn produce_bundle(
    file_bytes: &[u8],
    sender_keys: &SenderKeyFile,
    receiver_keys: &ReceiverKeyFile,
    context: Option<&str>,
) -> Result<Bundle, AttestError> {
    let context = context.unwrap_or(CONTEXT_LABEL).to_string();
    let file_digest = file_digest(file_bytes);
    let sender_signing_key = signing_key_from_seed_b64(&sender_keys.seed_b64)?;
    let sender_public_key = sender_signing_key.verifying_key().encode().to_vec();
    let receiver_pk = B64.decode(&receiver_keys.public_key_b64)?;

    let mut validation_secret = [0u8; VALIDATION_SECRET_LEN];
    getrandom::fill(&mut validation_secret).map_err(|_| AttestError::RandomGeneration)?;

    let mut hpke = default_hpke();
    let (enc, ct) = hpke
        .seal(
            &receiver_pk,
            context.as_bytes(),
            file_digest.as_slice(),
            &validation_secret,
            None,
            None,
            None,
        )
        .map_err(|e| AttestError::Hpke(format!("{e:?}")))?;

    let receiver_tag = hmac_file_digest(&validation_secret, &file_digest)?;
    let transcript = build_transcript(
        VERSION,
        context.as_bytes(),
        enc.as_slice(),
        ct.as_slice(),
        &file_digest,
        &receiver_tag,
        &sender_public_key,
    );
    let sig = sender_signing_key.sign(&transcript);
    validation_secret.zeroize();

    Ok(Bundle {
        version: VERSION,
        file_digest,
        receiver_tag,
        hpke_enc: enc,
        hpke_ct: ct,
        sender_public_key,
        sender_signature: sig.to_bytes().to_vec(),
        context,
    })
}

pub fn verify_bundle(
    file_bytes: &[u8],
    trusted_sender_public_key_b64: &str,
    receiver_private_key_b64: &str,
    bundle: &Bundle,
) -> Result<VerificationOutcome, AttestError> {
    let expected_digest = file_digest(file_bytes);
    if !bool::from(expected_digest.as_slice().ct_eq(bundle.file_digest.as_slice())) {
        return Err(AttestError::FileDigestMismatch);
    }

    let trusted_sender_pk_bytes = B64.decode(trusted_sender_public_key_b64)?;
    if !bool::from(trusted_sender_pk_bytes.as_slice().ct_eq(bundle.sender_public_key.as_slice())) {
        return Err(AttestError::SenderPublicKeyMismatch);
    }

    let mut hpke = default_hpke();
    let receiver_sk = B64.decode(receiver_private_key_b64)?;
    let recovered_secret = hpke
        .open(
            &bundle.hpke_enc,
            &receiver_sk,
            bundle.context.as_bytes(),
            expected_digest.as_slice(),
            &bundle.hpke_ct,
            None,
            None,
            None,
        )
        .map_err(|e| AttestError::Hpke(format!("{e:?}")))?;

    let expected_tag = hmac_file_digest(&recovered_secret, &expected_digest)?;
    if !bool::from(expected_tag.as_slice().ct_eq(bundle.receiver_tag.as_slice())) {
        return Err(AttestError::ReceiverTagMismatch);
    }

    let sender_pk = verifying_key_from_bytes(&bundle.sender_public_key)?;
    let sig = signature_from_bytes(&bundle.sender_signature)?;
    let transcript = build_transcript(
        bundle.version,
        bundle.context.as_bytes(),
        &bundle.hpke_enc,
        &bundle.hpke_ct,
        &bundle.file_digest,
        &bundle.receiver_tag,
        &bundle.sender_public_key,
    );
    sender_pk
        .verify(&transcript, &sig)
        .map_err(|_| AttestError::SignatureVerificationFailed)?;

    Ok(VerificationOutcome {
        file_digest_valid: true,
        receiver_tag_valid: true,
        sender_signature_valid: true,
        file_digest_hex: hex_of(&expected_digest),
    })
}

pub fn file_digest(file_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(file_bytes);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; FILE_DIGEST_LEN];
    reader.read(&mut out);
    out.to_vec()
}

pub fn hmac_file_digest(secret: &[u8], file_digest: &[u8]) -> Result<Vec<u8>, AttestError> {
    type MacSha256 = Hmac<sha2::Sha256>;
    let mut mac = MacSha256::new_from_slice(secret).map_err(|e| AttestError::Hpke(format!("{e:?}")))?;
    mac.update(file_digest);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn build_transcript(
    version: u8,
    context: &[u8],
    hpke_enc: &[u8],
    hpke_ct: &[u8],
    file_digest: &[u8],
    receiver_tag: &[u8],
    sender_public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, CONTEXT_LABEL.as_bytes());
    out.push(version);
    append_len_prefixed(&mut out, context);
    append_len_prefixed(&mut out, hpke_enc);
    append_len_prefixed(&mut out, hpke_ct);
    append_len_prefixed(&mut out, file_digest);
    append_len_prefixed(&mut out, receiver_tag);
    append_len_prefixed(&mut out, sender_public_key);
    out
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("value too long");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn default_hpke() -> DefaultHpke {
    DefaultHpke::new(
        Mode::Base,
        KemAlgorithm::MlKem768,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

fn signing_key_from_seed_b64(seed_b64: &str) -> Result<SigningKey<MlDsa65>, AttestError> {
    let seed_bytes = B64.decode(seed_b64)?;
    let seed_arr: [u8; 32] = seed_bytes.try_into().map_err(|_| AttestError::InvalidSenderSeedLength)?;
    Ok(SigningKey::<MlDsa65>::from_seed(&seed_arr.into()))
}

fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>, AttestError> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| AttestError::InvalidSenderPublicKey)?;
    Ok(VerifyingKey::<MlDsa65>::decode(&enc))
}

fn signature_from_bytes(bytes: &[u8]) -> Result<Signature<MlDsa65>, AttestError> {
    let enc = EncodedSignature::<MlDsa65>::try_from(bytes).map_err(|_| AttestError::InvalidSenderSignature)?;
    Signature::<MlDsa65>::decode(&enc).ok_or(AttestError::InvalidSenderSignature)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
