use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use clap::Parser;
use libcrux::signature::MlDsa65SigningKey;
use dvs_crypto_lib::{create_audit_token, AuditToken, MLDSA_65_PRIV_LEN};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "producer", version, about = "PQC DVS Producer CLI Engine", long_about = None)]
struct ProducerArgs {
    /// Path to the target payload file to be signed
    #[arg(short, long, value_name = "FILE")]
    file: PathBuf,

    /// Path to the long-term static ML-DSA private key file
    #[arg(long, value_name = "MLDSA_PRIV_KEY")]
    mldsa_priv: PathBuf,

    /// Path to the long-term static ML-DSA public key file
    #[arg(long, value_name = "MLDSA_PUB_KEY")]
    mldsa_pub: PathBuf,

    /// Path to the Auditor's pre-shared ML-KEM public key file
    #[arg(long, value_name = "MLKEM_PUB_KEY")]
    mlkem_pub: PathBuf,

    /// Optional custom path for the generated output package artifact
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ProducerArgs::parse();

    println!("[PRODUCER] Ingesting parameters via CLI runtime arguments...");

    // 1. Read input key parameters from user-provided paths
    let auditor_pub_bytes = std::fs::read(&args.mlkem_pub)
        .map_err(|e| format!("Critical: Failed to read Auditor ML-KEM public key at {:?}: {}", args.mlkem_pub, e))?;

    let mut producer_private_bytes = std::fs::read(&args.mldsa_priv)
        .map_err(|e| format!("Critical: Failed to read Producer ML-DSA private key at {:?}: {}", args.mldsa_priv, e))?;
        
    let producer_public_bytes = std::fs::read(&args.mldsa_pub)
        .map_err(|e| format!("Critical: Failed to read Producer ML-DSA public key at {:?}: {}", args.mldsa_pub, e))?;

    if producer_private_bytes.len() != MLDSA_65_PRIV_LEN {
        return Err("Corrupted private key length profile detected.".into());
    }

    // Allocate key structures and immediately overwrite raw transient heap elements
    let mut priv_array = [0u8; MLDSA_65_PRIV_LEN];
    priv_array.copy_from_slice(&producer_private_bytes);
    let encoder_signing_key = MlDsa65SigningKey::from(priv_array);
    producer_private_bytes.zeroize(); 

    // 2. Stream target payload file bytes from disk
    let mut file = File::open(&args.file)
        .map_err(|e| format!("Critical: Failed to open target file {:?}: {}", args.file, e))?;
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)?;

    // 3. Compute the compliance token package
    let token: AuditToken = create_audit_token(
        &file_bytes, 
        &auditor_pub_bytes, 
        &encoder_signing_key, 
        &producer_public_bytes
    )?;

    // 4. Determine output file target path logic
    let out_path = args.output.unwrap_or_else(|| {
        let mut default_out = args.file.clone();
        if let Some(ext) = default_out.extension() {
            let mut new_ext = ext.to_os_string();
            new_ext.push(".dvs.pkg");
            default_out.set_extension(new_ext);
        } else {
            default_out.set_extension("dvs.pkg");
        }
        default_out
    });

    // 5. Emit serialized package out to file destination
    let packaged_token_bytes = bincode::serialize(&token)?;
    std::fs::write(&out_path, &packaged_token_bytes)
        .map_err(|e| format!("Critical: Failed to write output package file to {:?}: {}", out_path, e))?;

    println!("[PRODUCER SUCCESS] DVS Token packet written safely to: {:?}", out_path);
    Ok(())
}
