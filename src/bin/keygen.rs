use pq_drse_lib::{generate_receiver_key_file, generate_sender_key_file};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from("./out");
    fs::create_dir_all(&out_dir)?;

    let sender = generate_sender_key_file()?;
    let receiver = generate_receiver_key_file()?;

    fs::write(
        out_dir.join("sender_keys.json"),
        serde_json::to_string_pretty(&sender)?,
    )?;
    fs::write(
        out_dir.join("receiver_keys.json"),
        serde_json::to_string_pretty(&receiver)?,
    )?;

    println!("Wrote ./out/sender_keys.json and ./out/receiver_keys.json");
    Ok(())
}
