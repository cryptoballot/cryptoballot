use cryptoballot::*;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

pub fn command_vote(matches: &clap::ArgMatches, uri: &str, secret_key: Option<&SecretKey>) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        let post = matches.is_present("post");
        command_vote_generate(matches, uri, secret_key, post);
        std::process::exit(0);
    }
}

pub fn command_vote_generate(
    matches: &clap::ArgMatches,
    uri: &str,
    secret_key: Option<&SecretKey>,
    post: bool,
) {
    let mut rng = rand::thread_rng();
    let secret_key: SecretKey = match secret_key {
        Some(sk) => ed25519_dalek::SecretKey::from_bytes(sk.as_ref()).unwrap(),
        None => {
            let keypair = ed25519_dalek::Keypair::generate(&mut rng);
            keypair.secret
        }
    };

    let public_key: PublicKey = (&secret_key).into();
    let election_id = crate::expand(matches.value_of("ELECTION-ID").unwrap());
    let secret_vote = crate::expand(matches.value_of("VOTE").unwrap());

    let selection = Selection {
        write_in: true,
        score: 0,
        selection: secret_vote,
    };

    // Get the encryption-key
    let enc_id = cryptoballot::Identifier::new_from_str_id(
        &election_id,
        TransactionType::EncryptionKey,
        None,
    )
    .unwrap_or_else(|| {
        // TODO: Replace with real error
        panic!("Invalid election-id");
    });

    // TODO: Replace with real error
    let encryption_key_tx = crate::rest::get_transaction(uri, enc_id)
        .expect("Unable to get encryption_key transaction");
    let encryption_key_tx: EncryptionKeyTransaction = encryption_key_tx.into();

    // Encrypt the secret vote
    // TODO: Real error not expect
    let encrypted_selections =
        cryptoballot::encrypt_vote(&encryption_key_tx.encryption_key, vec![selection], &mut rng)
            .expect("Error encrypting vote");

    // Generate an empty vote transaction
    let election_id = encryption_key_tx.election;
    let vote = VoteTransaction {
        id: VoteTransaction::build_id(election_id, &public_key),
        election: election_id,
        ballot_id: "BALLOT1".to_string(),
        encrypted_votes: vec![EncryptedVote {
            contest_index: 0,
            selections: encrypted_selections,
        }],
        anonymous_key: public_key,
        authentication: vec![],
    };

    // TODO: Normally we would do blind authentication here, but this is just for testing for now so skip

    // Sign and seal the vote transaction
    let vote: SignedTransaction = Signed::sign(&secret_key, vote).unwrap().into();

    let tx_json = serde_json::to_string_pretty(&vote).unwrap();
    println!("{}", tx_json);

    // Post it or print it
    if post {
        // TODO: post_transaction should return a result with an Err(string) if there's an error
        let _res = crate::rest::post_transaction(uri, vote, Some(&secret_key));
    }
}
