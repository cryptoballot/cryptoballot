use cryptoballot::Signed;
use cryptoballot::SignedTransaction;
use cryptoballot::TransactionType;
use cryptoballot::VotingEndTransaction;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

pub fn command_voting_end(matches: &clap::ArgMatches, uri: &str, secret_key: Option<&SecretKey>) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        let post = matches.is_present("post");

        let secret_key = secret_key.unwrap_or_else(|| {
            eprintln!(
                "Please provide a secret key either via --secret-key or CRYPTOBALLOT_SECRET_KEY"
            );
            std::process::exit(1);
        });

        command_voting_end_generate(matches, uri, secret_key, post);
        std::process::exit(0);
    }
}

pub fn command_voting_end_generate(
    matches: &clap::ArgMatches,
    uri: &str,
    secret_key: &SecretKey,
    post: bool,
) {
    let public_key: PublicKey = (secret_key).into();

    let election_id = crate::expand(matches.value_of("ELECTION-ID").unwrap());
    let election_id = cryptoballot::Identifier::new_from_str_id(
        &election_id,
        TransactionType::Election,
        &[0; 16],
    )
    .unwrap_or_else(|| {
        // TODO: Replace with real error
        panic!("Invalid election-id");
    });

    // Create a voting-end transaction
    let voting_end_tx = VotingEndTransaction::new(election_id, public_key);

    //  Turn it into a signed transaction
    let voting_end_tx = Signed::sign(&secret_key, voting_end_tx).unwrap();
    let voting_end_tx: SignedTransaction = voting_end_tx.into();

    // Serialize it and print it
    let tx_json = serde_json::to_string_pretty(&voting_end_tx).unwrap();
    println!("{}", tx_json);

    if post {
        // TODO: post_transaction should return a result with an Err(string) if there's an error
        let _res = crate::rest::post_transaction(uri, voting_end_tx, Some(&secret_key));
    }
}
