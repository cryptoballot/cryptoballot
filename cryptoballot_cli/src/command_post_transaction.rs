use cryptoballot::SignedTransaction;
use cryptoballot::Transaction;
use ed25519_dalek::SecretKey;

pub fn command_post_transaction(
    matches: &clap::ArgMatches,
    uri: &str,
    secret_key: Option<&SecretKey>,
) {
    let filename = crate::expand(matches.value_of("INPUT").unwrap());

    let file_bytes = match std::fs::read(&filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cryptoballot post: unable to read {}: {}, ", &filename, e);
            std::process::exit(1);
        }
    };

    let json_string = String::from_utf8(file_bytes).unwrap_or_else(|_| {
        eprintln!("cryptoballot post: Input file must be in JSON format");
        std::process::exit(1);
    });
    let json_string = json_string.trim();

    // If the first letter is `[` then it's a vector of transactions
    if json_string.chars().nth(0) == Some('[') {
        let txs: Vec<SignedTransaction> = serde_json::from_str(&json_string).unwrap_or_else(|e| {
            eprintln!(
                "cryptoballot post: error deserializing transaction list: {}",
                e
            );
            std::process::exit(1);
        });

        // There needs to be at least 1 block between diffeent types of transactions
        if txs.len() != 0 {
            let mut tx_type = txs[0].transaction_type();
            for tx in txs {
                if tx.transaction_type() != tx_type {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    tx_type = tx.transaction_type();
                }
                crate::rest::post_transaction(uri, tx, secret_key);
            }
        }
    } else {
        let tx: SignedTransaction = serde_json::from_str(&json_string).unwrap_or_else(|e| {
            // Maybe it's an unsigned transaction?
            let unsigned: Result<Transaction, _> = serde_json::from_str(&json_string);
            if unsigned.is_ok() {
                eprintln!(
                    "cryptoballot post: {} is unsigned, use `cryptoballot sign` to sign it first",
                    filename
                );
            } else {
                eprintln!("cryptoballot post: unable to read {}: {}, ", &filename, e);
            }

            std::process::exit(1);
        });

        crate::rest::post_transaction(uri, tx, secret_key);
    }
}
