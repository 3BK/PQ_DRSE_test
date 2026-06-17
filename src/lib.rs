use libcrux::kem::{MlKem768PrivateKey, MlKem768PublicKey, MlKem768Ciphertext};
use libcrux::signature::{MlDsa65SigningKey, MlDsa65VerificationKey, MlDsa65Signature};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad};
use aws_lc_rs::digest::{digest, SHA256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Explicit structural byte sizing definitions (Resolves CWE-20 input validation)
pub const MLKEM_768_PUB_LEN: usize = 1184;
pub const MLKEM_768_PRIV_LEN: usize = 2400;
pub const MLKEM_768_CT_LEN: usize = 1088;
pub const MLDSA_65_PUB_LEN: usize = 1952;
pub const MLDSA_65_SIG_LEN: usize = 3309;
pub const HASH_LEN: usize = 32;

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AuditToken {
    pub mlkem_ciphertext: Vec<u8>,
    pub mldsa_public_key: Vec<u8>,
    pub encrypted_payload_hash: Vec<u8>,
    pub aes_nonce: [u8; 12],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKeyBuffer {
    key_bytes: [u8; 32],
}

/// Generates a post-quantum DVS token over a file buffer using verified libcrux parameters.
pub fn create_audit_token(
    file_bytes: &[u8],
    auditor_mlkem_pub_bytes: &[u8],
    encoder_mldsa_signing_key: &MlDsa65SigningKey,
    encoder_mldsa_pub_bytes: &[u8],
) -> Result<AuditToken, Unspecified> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    
    // Enforce incoming public identity boundary checks (CWE-20 Input Validation)
    if auditor_mlkem_pub_bytes.len() != MLKEM_768_PUB_LEN || encoder_mldsa_pub_bytes.len() != MLDSA_65_PUB_LEN {
        return Err(Unspecified);
    }
    
    let mut pub_array = [0u8; MLKEM_768_PUB_LEN];
    pub_array.copy_from_slice(auditor_mlkem_pub_bytes);
    let auditor_pub_key = MlKem768PublicKey::from(pub_array);

    // Encapsulate via libcrux (Mitigation for KyberSlash execution timing channels)
    let (ciphertext, shared_secret) = auditor_pub_key.encapsulate();
    let mut raw_shared_secret = shared_secret.as_ref().to_vec();

    // Derive symmetric encryption parameters via HKDF
    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(&raw_shared_secret);
    let okm = prk.expand(&[b"libcrux-pq-dvs-context"], HKDF_SHA256)?;
    
    let mut secret_holder = SecretKeyBuffer { key_bytes: [0u8; 32] };
    okm.fill(&mut secret_holder.key_bytes)?;
    raw_shared_secret.zeroize(); // Purge secret material out of RAM (CWE-591)

    let file_hash = digest(&SHA256, file_bytes);
    
    // Construct flat transaction binding payload
    let mut binding_payload = Vec::with_capacity(HASH_LEN + MLKEM_768_CT_LEN);
    binding_payload.extend_from_slice(file_hash.as_ref());
    binding_payload.extend_from_slice(ciphertext.as_ref());
    
    let signature = encoder_mldsa_signing_key
        .sign(&binding_payload)
        .map_err(|_| Unspecified)?;

    // Package signature elements inside the authenticated AEAD envelope
    let mut payload_to_encrypt = file_hash.as_ref().to_vec();
    payload_to_encrypt.extend_from_slice(signature.as_ref());

    let unbound_key = UnboundKey::new(&AES_256_GCM, &secret_holder.key_bytes)?;
    let safe_key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; 12];
    aws_lc_rs::rand::SystemRandom::new().fill(&mut nonce_bytes)?; // Hardware entropy compliance
    let aes_nonce = Nonce::assume_unique_header(nonce_bytes);

    safe_key.seal_in_place_append_tag(
        aes_nonce,
        Aad::from(b"libcrux-dvs-metadata"),
        &mut payload_to_encrypt,
    )?;

    Ok(AuditToken {
        mlkem_ciphertext: ciphertext.as_ref().to_vec(),
        mldsa_public_key: encoder_mldsa_pub_bytes.to_vec(),
        encrypted_payload_hash: payload_to_encrypt,
        aes_nonce: nonce_bytes,
    })
}

/// Open, decrypt, and perform structural validation checks on an incoming token bundle.
pub fn validate_audit_token(
    file_bytes: &[u8],
    token: &AuditToken,
    auditor_mlkem_priv_key: &MlKem768PrivateKey,
) -> Result<bool, Unspecified> {
    // Validate exact byte packet bounds before memory translation (CWE-20 Input Validation)
    if token.mlkem_ciphertext.len() != MLKEM_768_CT_LEN 
        || token.mldsa_public_key.len() != MLDSA_65_PUB_LEN 
        || token.encrypted_payload_hash.len() < (HASH_LEN + MLDSA_65_SIG_LEN) {
        return Ok(false); 
    }

    let mut ct_array = [0u8; MLKEM_768_CT_LEN];
    ct_array.copy_from_slice(&token.mlkem_ciphertext);
    let ciphertext = MlKem768Ciphertext::from(ct_array);

    let shared_secret = auditor_mlkem_priv_key.decapsulate(&ciphertext);
    let mut raw_shared_secret = shared_secret.as_ref().to_vec();

    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(&raw_shared_secret);
    let okm = prk.expand(&[b"libcrux-pq-dvs-context"], HKDF_SHA256)?;
    
    let mut secret_holder = SecretKeyBuffer { key_bytes: [0u8; 32] };
    okm.fill(&mut secret_holder.key_bytes)?;
    raw_shared_secret.zeroize();

    let unbound_key = UnboundKey::new(&AES_256_GCM, &secret_holder.key_bytes)?;
    let safe_key = LessSafeKey::new(unbound_key);
    let aes_nonce = Nonce::assume_unique_header(token.aes_nonce);

    let mut decrypted_payload = token.encrypted_payload_hash.clone();
    
    // Evaluate AES decryption. Catch tag verification failures cleanly without panics.
    let validated_slice = match safe_key.open_in_place(
        aes_nonce,
        Aad::from(b"libcrux-dvs-metadata"),
        &mut decrypted_payload,
    ) {
        Ok(slice) => slice,
        Err(_) => {
            decrypted_payload.zeroize();
            return Ok(false);
        }
    };

    let (embedded_hash, signature_bytes) = validated_slice.split_at(HASH_LEN);

    let expected_file_hash = digest(&SHA256, file_bytes);
    if embedded_hash != expected_file_hash.as_ref() {
        decrypted_payload.zeroize();
        return Ok(false);
    }

    // Rebuild flattened slice structures to run constant-time matrix validation checks
    let mut binding_payload = Vec::with_capacity(HASH_LEN + MLKEM_768_CT_LEN);
    binding_payload.extend_from_slice(expected_file_hash.as_ref());
    binding_payload.extend_from_slice(&token.mlkem_ciphertext);

    let mut pub_key_array = [0u8; MLDSA_65_PUB_LEN];
    pub_key_array.copy_from_slice(&token.mldsa_public_key);
    let verification_key = MlDsa65VerificationKey::from(pub_key_array);

    let mut sig_array = [0u8; MLDSA_65_SIG_LEN];
    sig_array.copy_from_slice(signature_bytes);
    let signature = MlDsa65Signature::from(sig_array);

    let signature_is_valid = verification_key.verify(&binding_payload, &signature).is_ok();
    
    decrypted_payload.zeroize(); // Scrub transient memory bounds out of scope
    Ok(signature_is_valid)
}
