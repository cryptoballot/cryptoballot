use cryptoballot_exonum::Transaction;
use reqwest::header::CONTENT_TYPE;

pub fn command_post_transaction(matches: &clap::ArgMatches, uri: &str) {
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

    let exonum_tx: Transaction = tx.into();

    // TODO: Use real keys
    let (public_key, sercet_key) = exonum_crypto::gen_keypair();
    let transaction_hex = exonum_tx.into_transaction_hex(public_key, &sercet_key);

    let client = reqwest::blocking::Client::new();
    let full_url = format!("{}/api/explorer/v1/transactions", uri);

    let res = client
        .post(&full_url)
        .json(&transaction_hex)
        .send()
        .unwrap();

    let res = res.text().unwrap();

    println!("{}", res);
}
