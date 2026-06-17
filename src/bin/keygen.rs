use libcrux::kem::MlKem768KeyPair;
use libcrux::signature::MlDsa65KeyPair;
use mimalloc::MiMalloc;
use std::fs::create_dir_all;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[KEYGEN] Generating production long-term static identities...");
    create_dir_all("vault")?;

    // 1. Auditor Long-Term Identity Configuration
    let auditor_keypair = MlKem768KeyPair::generate();
    std::fs::write("vault/auditor_mlkem_public.key", auditor_keypair.public_key().as_ref())?;
    std::fs::write("vault/auditor_mlkem_private.key", auditor_keypair.private_key().as_ref())?;

    // 2. Producer Long-Term Identity Configuration
    let producer_keypair = MlDsa65KeyPair::generate();
    std::fs::write("vault/producer_mldsa_public.key", producer_keypair.verification_key().as_ref())?;
    std::fs::write("vault/producer_mldsa_private.key", producer_keypair.signing_key().as_ref())?;

    println!("[KEYGEN] Initial identities written to local vault storage directory.");
    Ok(())
}
