pub fn command_keygen(_matches: &clap::ArgMatches) {
    let (secret, public) = cryptoballot::generate_keypair();
    let (secret, public) = (
        hex::encode(secret.to_bytes()),
        hex::encode(public.to_bytes()),
    );

    println!("secret-key: {}", secret);
    println!("public-key: {}", public);
}
