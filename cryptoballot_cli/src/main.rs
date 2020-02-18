#![feature(inner_deref)]

use clap::{App, Arg, SubCommand};
use num_enum::TryFromPrimitive;
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::CryptoFactory;

mod transaction;

#[derive(TryFromPrimitive, PartialEq, Copy, Clone)]
#[repr(u8)]
enum Verbosity {
    Silent = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
}
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
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(
            SubCommand::with_name("post")
                .about("Post transaction(s)")
                .arg(
                    Arg::with_name("INPUT")
                        .index(1)
                        .required(true) // TODO: allow stdin
                        .help("Transaction file in JSON or CBOR format"),
                ),
        )
        .get_matches();

    let verbosity = match matches.occurrences_of("v") {
        0 => Verbosity::Warn,
        1 => Verbosity::Info,
        _ => Verbosity::Warn,
    };

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let env_var = std::env::var("CRYPTOBALLOT_URI");
    let uri = match matches.value_of("uri") {
        Some(uri) => uri,
        None => env_var.as_deref().unwrap_or("http://localhost:4692"),
    };
    if verbosity as u8 >= 3 {
        println!("URI: {}", uri);
    }

    // Subcommands
    if let Some(matches) = matches.subcommand_matches("post") {
        command_post_transaction(matches, uri, verbosity);
    }
}

fn command_post_transaction(matches: &clap::ArgMatches, uri: &str, verbosity: Verbosity) {
    use content_inspector::ContentType;

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

    let tx: cryptoballot::Transaction = match content_inspector::inspect(&file_bytes) {
        ContentType::UTF_8 => serde_json::from_slice(&file_bytes).unwrap_or_else(|e| {
            eprintln!("cryptoballot post: unable to read {}: {}, ", filename, e);
            std::process::exit(1);
        }),
        ContentType::BINARY => serde_cbor::from_slice(&file_bytes).unwrap_or_else(|e| {
            eprintln!("cryptoballot post: unable to read {}: {}, ", filename, e);
            std::process::exit(1);
        }),
        _ => {
            eprintln!("cryptoballot post: invalid file format for {}", filename);
            std::process::exit(1);
        }
    };

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
    transaction::send_batch_list(bl);
}
