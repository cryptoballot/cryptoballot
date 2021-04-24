use crate::expand;
use cryptoballot::MemStore;
use cryptoballot::SignedTransaction;

pub fn command_e2e(matches: &clap::ArgMatches) {
    let filename = expand(matches.value_of("INPUT").unwrap());

    let file_bytes = match std::fs::read(&filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cryptoballot e2e: unable to read {}: {}, ", &filename, e);
            std::process::exit(1);
        }
    };

    let mut store = MemStore::default();

    let transactions: Vec<SignedTransaction> =
        serde_json::from_slice(&file_bytes).expect("Unable to parse transactions");

    for tx in transactions {
        match tx.validate(&store) {
            Ok(()) => store.set(tx),
            Err(e) => {
                eprint!("Failed to validate transaction {}: {}", tx.id(), e);
                std::process::exit(1)
            }
        }
    }

    println!("OK");
}
