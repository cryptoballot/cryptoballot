use super::expand;
use cryptoballot::Authenticator;
use cryptoballot::ElectionTransaction;
use cryptoballot::Signed;
use cryptoballot::SignedTransaction;
use cryptoballot::Trustee;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use std::fs::read_to_string;

pub fn command_election(matches: &clap::ArgMatches, uri: &str, secret_key: Option<&SecretKey>) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        let secret_key = secret_key.unwrap_or_else(|| {
            eprintln!(
                "Please provide a secret key either via --secret-key or CRYPTOBALLOT_SECRET_KEY"
            );
            std::process::exit(1);
        });

        command_election_generate(matches, uri, secret_key);
        std::process::exit(0);
    }
}

pub fn command_election_generate(matches: &clap::ArgMatches, uri: &str, secret_key: &SecretKey) {
    let public_key: PublicKey = (secret_key).into();

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(public_key.clone());
    election.ballots = vec![uuid::Uuid::nil()];
    election.authenticators_threshold = 0;

    // Generate a trustee
    let (_ecies_secret, ecies_key) = Trustee::ecies_keys(&secret_key);

    let trustee = Trustee {
        id: uuid::Uuid::new_v4(),
        index: 1,
        public_key,
        ecies_key,
        num_trustees: 1,
        threshold: 1,
    };
    election.trustees = vec![trustee];

    //  Turn it into a signed transaction
    let election_tx = Signed::sign(&secret_key, election).unwrap();
    let election_tx: SignedTransaction = election_tx.into();

    // Serialize it and print it
    let election_tx = serde_json::to_string_pretty(&election_tx).unwrap();
    println!("{}", election_tx);
}
