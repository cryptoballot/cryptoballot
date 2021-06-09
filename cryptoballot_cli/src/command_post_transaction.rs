use cryptoballot_exonum::Transaction;
use ed25519_dalek::SecretKey;
use reqwest::header::CONTENT_TYPE;

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

    let tx = cryptoballot::SignedTransaction::from_bytes(&file_bytes).unwrap_or_else(|e| {
        // Maybe it's an unsigned transaction?
        if cryptoballot::Transaction::from_bytes(&file_bytes).is_ok() {
            eprintln!(
                "cryptoballot post: {} is unsigned, use `cryptoballot sign` to sign it first",
                filename
            );
        } else {
            eprintln!("cryptoballot post: unable to read {}: {}, ", &filename, e);
        }

        std::process::exit(1);
    });

    let response = crate::rest::post_transaction(uri, tx, secret_key);
    println!("{}", response);
}
