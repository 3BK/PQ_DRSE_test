use pq_hpke_file_attest_mlkem::{produce_bundle, Bundle, ReceiverKeyFile, SenderKeyFile};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: cargo run --bin producer -- <sender_keys.json> <receiver_keys.json> <input_file> <output_bundle.json>");
        std::process::exit(2);
    }

    let sender: SenderKeyFile = serde_json::from_slice(&fs::read(&args[1])?)?;
    let receiver: ReceiverKeyFile = serde_json::from_slice(&fs::read(&args[2])?)?;
    let input = fs::read(&args[3])?;

    let bundle: Bundle = produce_bundle(&input, &sender, &receiver, Some("producer-file-attestation-mlkem-shake256"))?;
    fs::write(&args[4], bundle.to_json_pretty()?)?;

    println!("Wrote bundle to {}", &args[4]);
    Ok(())
}
