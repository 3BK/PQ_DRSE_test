use pq_drse_lib::{verify_bundle, Bundle, ReceiverKeyFile};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cargo run --bin consumer -- <receiver_keys.json> <bundle.json> <input_file>");
        std::process::exit(2);
    }

    let receiver: ReceiverKeyFile = serde_json::from_slice(&fs::read(&args[1])?)?;
    let bundle = Bundle::from_json_str(&fs::read_to_string(&args[2])?)?;
    let input = fs::read(&args[3])?;

    let sender_pk_b64 = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&args[2])?)?["sender_mldsa65_public_key_b64"]
        .as_str()
        .ok_or("bundle missing sender_mldsa65_public_key_b64")?
        .to_string();

    let verdict = verify_bundle(&input, &sender_pk_b64, &receiver.private_key_b64, &bundle)?;

    println!("file_digest_valid    : {}", verdict.file_digest_valid);
    println!("receiver_tag_valid   : {}", verdict.receiver_tag_valid);
    println!("sender_signature_ok  : {}", verdict.sender_signature_valid);
    println!("shake256(file)       : {}", verdict.file_digest_hex);
    Ok(())
}
