use cryptoballot::ElectionTransaction;
use cryptoballot::Signed;
use cryptoballot::SignedTransaction;
use cryptoballot::Trustee;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

pub fn command_election(matches: &clap::ArgMatches, uri: &str, secret_key: Option<&SecretKey>) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        let post = matches.is_present("post");

        let secret_key = secret_key.unwrap_or_else(|| {
            eprintln!(
                "Please provide a secret key either via --secret-key or CRYPTOBALLOT_SECRET_KEY"
            );
            std::process::exit(1);
        });

        command_election_generate(uri, secret_key, post);
        std::process::exit(0);
    }
}

pub fn command_election_generate(uri: &str, secret_key: &SecretKey, post: bool) {
    let public_key: PublicKey = (secret_key).into();

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(public_key.clone());
    election.ballots = vec![uuid::Uuid::nil()];
    election.authenticators_threshold = 0;

    let trustee = Trustee {
        index: 1,
        public_key,
        num_trustees: 1,
        threshold: 1,
    };
    election.trustees = vec![trustee];

    //  Turn it into a signed transaction
    let election_tx = Signed::sign(&secret_key, election).unwrap();
    let election_tx: SignedTransaction = election_tx.into();

    // Serialize it and print it
    let election_tx_json = serde_json::to_string_pretty(&election_tx).unwrap();
    println!("{}", election_tx_json);

    if post {
        // TODO: post_transaction should return a result with an Err(string) if there's an error
        let _res = crate::rest::post_transaction(uri, election_tx, Some(&secret_key));
    }
}
