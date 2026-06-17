use clap::Parser;
use dvs_crypto_lib::{validate_audit_token, AuditToken, MLKEM_768_PRIV_LEN};
use libcrux::kem::MlKem768PrivateKey;
use mimalloc::MiMalloc;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroize;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;


#[derive(Parser, Debug)]
#[command(name = "consumer", version, about = "PQC DVS Consumer/Auditor CLI Engine", long_about = None)]
struct ConsumerArgs {
    /// Path to the data payload file to be audited
    #[arg(short, long, value_name = "FILE")]
    file: PathBuf,

    /// Path to the companion detached DVS validation package artifact
    #[arg(short, long, value_name = "PACKAGE_FILE")]
    package: PathBuf,

    /// Path to the local trusted vault copy of the expected Producer ML-DSA public key
    #[arg(long, value_name = "TRUSTED_PRODUCER_PUB_KEY")]
    trusted_producer_pub: PathBuf,

    /// Path to the Auditor's own long-term static ML-KEM private key file
    #[arg(long, value_name = "MLKEM_PRIV_KEY")]
    mlkem_priv: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ConsumerArgs::parse();

    println!("[CONSUMER] Initiating automated validation loop via CLI arguments...");

    // 1. Ingest targeted verification byte packages from input parameters
    let mut file = File::open(&args.file)
        .map_err(|e| format!("Critical: Failed to open file {:?}: {}", args.file, e))?;
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)?;

    let mut pkg_file = File::open(&args.package)
        .map_err(|e| format!("Critical: Failed to open package {:?}: {}", args.package, e))?;
    let mut pkg_bytes = Vec::new();
    pkg_file.read_to_end(&mut pkg_bytes)?;

    // Replace old bincode deserialization logic:
    // let token: AuditToken = bincode::deserialize(&pkg_bytes)?;
    
    // Use postcard's stack/slice parsing engine instead:
    let token: AuditToken = postcard::from_bytes(&pkg_bytes)
        .map_err(|e| format!("Deserialization Failure (Corrupted Token Package): {}", e))?;                  

    // 2. Enforce CWE-322 Mitigation: Validate identity matching against out-of-band anchor path
    let trusted_producer_pub_bytes = std::fs::read(&args.trusted_producer_pub)
        .map_err(|e| format!("Identity Failure: Unable to locate trusted anchor key at {:?}: {}", args.trusted_producer_pub, e))?;

    if token.mldsa_public_key != trusted_producer_pub_bytes {
        println!("SECURITY EXPLOIT BLOCKED] Token public identity does not match your trusted profile anchor!");
        std::process::exit(1);
    }

    // 3. Load private parameter state mapping
    let mut private_key_bytes = std::fs::read(&args.mlkem_priv)
        .map_err(|e| format!("Critical: Failed to read Auditor ML-KEM private key at {:?}: {}", args.mlkem_priv, e))?;
        
    if private_key_bytes.len() != MLKEM_768_PRIV_LEN {
        panic!("Invalid local private verification key allocation size mapped on disk.");
    }
    
    let mut priv_array = [0u8; MLKEM_768_PRIV_LEN];
    priv_array.copy_from_slice(&private_key_bytes);
    let auditor_private_key = MlKem768PrivateKey::from(priv_array);
    private_key_bytes.zeroize();

    // 4. Run verification logic against library
    let is_authentic = validate_audit_token(&file_bytes, &token, &auditor_private_key)?;

    if is_authentic {
        println!("[AUDIT PASS] Post-quantum signature matches trusted identity anchor. File is pristine.");
    } else {
        println!("[AUDIT PANIC] Cryptographic validation failed! Document has been tampered with or modified.");
        std::process::exit(1);
    }

    Ok(())
}
