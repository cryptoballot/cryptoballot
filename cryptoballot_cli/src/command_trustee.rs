use super::expand;
use cryptoballot::Trustee;
use std::fs::File;
use std::io::prelude::*;

pub fn command_trustee(matches: &clap::ArgMatches) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        command_trustee_generate(matches);
        std::process::exit(0);
    }
}

pub fn command_trustee_generate(matches: &clap::ArgMatches) {
    // Unwraps are OK, both these args are required
    let secret_location = expand(matches.value_of("secret").unwrap());

    let (trustee, secret) = Trustee::new(1, 1, 1);

    let secret = hex::encode(secret.to_bytes());

    let mut file = File::create(&secret_location).unwrap_or_else(|e| {
        eprintln!(
            "cryptoballot generate: cannot create file {}: {}",
            &secret_location, e
        );
        std::process::exit(1);
    });

    file.write_all(secret.as_bytes()).unwrap_or_else(|e| {
        eprintln!(
            "cryptoballot post: unable to write secret to {}: {}",
            &secret_location, e
        );
        std::process::exit(1);
    });

    let trustee = serde_json::to_string_pretty(&trustee).unwrap();

    println!("{}", trustee);
}
