use clap::{App, Arg, SubCommand};
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::CryptoFactory;

mod transaction;

fn main() {
    let matches = App::new("CryptoBallot CLI")
        .version("1.0")
        .author("Patrick Hayes <patrick.d.hayes@gmail.com>")
        .about("Interacts with a CryptoBallot server")
        .arg(
            Arg::with_name("uri")
                .help("Set the cryptoballot uri - can also be set with CRYPTOBALLOT_URI")
                .required(false),
        )
        .subcommand(
            SubCommand::with_name("sign").about("Sign transaction").arg(
                Arg::with_name("INPUT")
                    .index(1)
                    .required(true) // TODO: allow stdin
                    .help("Transaction file in JSON or CBOR format"),
            ),
        )
        .subcommand(
            SubCommand::with_name("post").about("Post transaction").arg(
                Arg::with_name("INPUT")
                    .index(1)
                    .required(true) // TODO: allow stdin
                    .help("Transaction file in JSON or CBOR format"),
            ),
        )
        .get_matches();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let env_var = std::env::var("CRYPTOBALLOT_URI");
    let uri = match matches.value_of("uri") {
        Some(uri) => uri.to_string(),
        None => env_var.unwrap_or("http://localhost:8008".to_string()),
    };

    // Subcommands
    if let Some(matches) = matches.subcommand_matches("post") {
        command_post_transaction(matches, &uri);
    }
}

fn command_post_transaction(matches: &clap::ArgMatches, uri: &str) {
    let filename = match matches.value_of("INPUT") {
        Some(filename) => filename,
        None => {
            eprintln!("cryptoballot post: input filename required");
            std::process::exit(1);
        }
    };

    let file_bytes = match std::fs::read(filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cryptoballot post: unable to read {}: {}, ", filename, e);
            std::process::exit(1);
        }
    };

    let tx = cryptoballot::SignedTransaction::from_bytes(&file_bytes).unwrap_or_else(|e| {
        eprintln!("cryptoballot post: unable to read {}: {}, ", filename, e);
        std::process::exit(1);
    });

    // Generate the signer
    // TODO: allow signer to be passed in
    let context = create_context("secp256k1").expect("Error creating the right context");
    let private_key = context
        .new_random_private_key()
        .expect("Error generating a new Private Key");
    let crypto_factory = CryptoFactory::new(context.as_ref());
    let signer = crypto_factory.new_signer(private_key.as_ref());

    // Create sawtooth transaction
    let tx = transaction::create_tx(&signer, &tx);
    let bl = transaction::create_batch_list(&signer, &tx);
    transaction::send_batch_list(bl, uri).unwrap_or_else(|e| {
        eprintln!("cryptoballot post: error sending transaction: {}, ", e);
        std::process::exit(1);
    });
}
