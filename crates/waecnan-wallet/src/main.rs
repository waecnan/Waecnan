use waecnan_wallet::wallet_from_seed;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "generate" => {
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = i as u8;
            }
            // In production: use rand::thread_rng
            let keys = wallet_from_seed(&seed);
            println!("Address: {}", keys.address);
            println!("Seed (hex): {}", hex::encode(seed));
            println!("KEEP YOUR SEED PRIVATE. IT CANNOT BE RECOVERED.");
        }
        "address" => {
            let seed_hex = args
                .get(2)
                .expect("Usage: waecnan-wallet address <seed_hex>");
            let bytes = hex::decode(seed_hex).expect("Invalid hex");
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            let keys = wallet_from_seed(&seed);
            println!("Address: {}", keys.address);
        }
        _ => {
            println!("Waecnan Wallet");
            println!("  generate          Generate a new wallet");
            println!("  address <seed>    Show address for a seed");
        }
    }
}
