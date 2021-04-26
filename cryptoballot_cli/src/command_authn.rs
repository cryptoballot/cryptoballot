use super::expand;
use cryptoballot::Authenticator;
use std::fs::File;
use std::io::prelude::*;

pub fn command_authn(matches: &clap::ArgMatches) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        command_authn_generate(matches);
        std::process::exit(0);
    }
}

pub fn command_authn_generate(matches: &clap::ArgMatches) {
    // Unwraps are OK, both these args are required
    let secret_location = expand(matches.value_of("secret").unwrap());
    let keysize: usize = matches
        .value_of("keysize")
        .unwrap()
        .parse()
        .expect("Invalid keysize");

    // TODO Check --quite
    if keysize < 2048 {
        eprintln!("cryptoballot: WARNING: Using insecure keysize for authn")
    }

    // For now just use the nil ballot id
    // TODO: Change this when we have ballot and contest system in place
    let ballot_ids = vec![uuid::Uuid::nil()];
    let (authn, secrets) = Authenticator::new(keysize, &ballot_ids).unwrap();

    let mut file = File::create(&secret_location).unwrap_or_else(|e| {
        eprintln!(
            "cryptoballot generate: cannot create file {}: {}",
            &secret_location, e
        );
        std::process::exit(1);
    });

    let secrets = serde_json::to_string_pretty(&secrets).unwrap();

    file.write_all(secrets.as_bytes()).unwrap_or_else(|e| {
        eprintln!(
            "cryptoballot post: unable to write secret to {}: {}",
            &secret_location, e
        );
        std::process::exit(1);
    });

    let authn = serde_json::to_string_pretty(&authn).unwrap();

    println!("{}", authn);
}
