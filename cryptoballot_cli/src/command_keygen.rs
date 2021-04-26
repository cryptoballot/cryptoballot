use super::expand;
use std::fs::File;
use std::io::prelude::*;

pub fn command_keygen(matches: &clap::ArgMatches) {
    // Unwraps are OK, both these args are required
    let secret_location = expand(matches.value_of("secret").unwrap());

    let (secret, public) = cryptoballot::generate_keypair();
    let (secret, public) = (
        hex::encode(secret.to_bytes()),
        hex::encode(public.to_bytes()),
    );

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

    println!("public-key: {}", public);
}
