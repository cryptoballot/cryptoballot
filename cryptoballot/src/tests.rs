use super::*;
use ed25519_dalek::SecretKey;
use uuid::Uuid;

#[test]
fn end_to_end_election() {
    let mut store = MemStore::default();

    // Create election authority public and private key
    let (authority_secret, authority_public) = generate_keypair();

    // Create a ballot (TODO: make this a proper struct)
    let ballot_id = Uuid::new_v4();

    // Create an authenticator
    let (authenticator, authn_secrets) = Authenticator::new(256, &vec![ballot_id]).unwrap();
    let authn_secret = authn_secrets.get(&ballot_id).unwrap();
    let authn_public = authenticator.public_keys.get(&ballot_id).unwrap().as_ref();

    // Create 3 trustees
    let (trustee_1, trustee_1_secret) = Trustee::new();
    let (trustee_2, trustee_2_secret) = Trustee::new();
    let (trustee_3, _trustee_3_secret) = Trustee::new();

    // Create an election transaction with a single ballot
    let (mut election, election_secret) = ElectionTransaction::new(authority_public);
    election.ballots = vec![ballot_id];
    election.authenticators = vec![authenticator.clone()];
    election.trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];
    election.trustees_threshold = 2;

    // Finalize election transaction by signing it
    let election = Signed::sign(&authority_secret, election).unwrap();

    // Deal the secret shares to the trustees
    let mut shares = deal_secret_shares(
        election.trustees_threshold,
        election.trustees.len(),
        election_secret.as_bytes(),
    );
    let trustee_1_share = shares.pop().unwrap();
    let trustee_2_share = shares.pop().unwrap();

    // TODO: In the future, don't rely on a trusted dealer, instead do verifiable distributed key generation using ElGamal

    // Validate the election transaction and store it
    election.verify_signature().unwrap();
    election.validate(&store).unwrap();
    store.set(election.clone().into());

    // Generate an empty vote transaction
    let (mut vote, voter_secret) = VoteTransaction::new(election.id(), ballot_id);

    // Create an auth package and blind it
    let auth_package = AuthPackage::new(election.id(), ballot_id, vote.anonymous_key);
    let (blinded_auth_package, unblinder) = auth_package.blind(&authn_public);

    // Authenticate the voter (for a real election the voter would pass additional auth info)
    let authentication = authenticator.authenticate(&authn_secret, &blinded_auth_package);
    let authentication = authentication.unblind(&authn_public, unblinder);
    vote.authentication.push(authentication);

    // Create a vote transaction
    let secret_vote = "Barak Obama";

    // Encrypt the secret vote
    vote.encrypted_vote =
        encrypt_vote(&election.encryption_public, secret_vote.as_bytes()).unwrap();

    // Sign and seal the vote transaction
    let vote = Signed::sign(&voter_secret, vote).unwrap();

    // Validate the vote transaction and store it
    vote.verify_signature().unwrap();
    vote.validate(&store).unwrap();
    store.set(vote.clone().into());

    // Voting is over
    // ----------------

    // Create SecretShare transactions - only 2 of 3!
    let secret_share_1 = SecretShareTransaction::new(election.id(), trustee_1, trustee_1_share);
    let secret_share_2 = SecretShareTransaction::new(election.id(), trustee_2, trustee_2_share);

    // Sign and seal Secretshare transactions
    let secret_share_1 = Signed::sign(&trustee_1_secret, secret_share_1).unwrap();
    let secret_share_2 = Signed::sign(&trustee_2_secret, secret_share_2).unwrap();

    // Validate SecretShare transactions
    secret_share_1.verify_signature().unwrap();
    secret_share_1.validate(&store).unwrap();
    store.set(secret_share_1.clone().into());

    secret_share_2.verify_signature().unwrap();
    secret_share_2.validate(&store).unwrap();
    store.set(secret_share_2.clone().into());

    // Sign the secret-share transaction

    // Recover election key from two trustees
    let shares = vec![
        secret_share_1.secret_share.clone(),
        secret_share_2.secret_share.clone(),
    ];
    let election_key = recover_secret_from_shares(election.trustees_threshold, shares).unwrap();
    let election_key = SecretKey::from_bytes(&election_key).unwrap();

    // Decrypt the votes
    let decrypted_vote = decrypt_vote(&election_key, &vote.encrypted_vote).unwrap();

    // Create decryption transaction
    let trustees: Vec<Uuid> = election.trustees.iter().map(|t| t.id).collect();
    let decryption = DecryptionTransaction::new(election.id(), vote.id(), trustees, decrypted_vote);
    let decryption = Signed::sign(&authority_secret, decryption).unwrap();

    // Validate the vote transaction
    decryption.verify_signature().unwrap();
    decryption.validate(&store).unwrap();
    store.set(decryption.clone().into());

    // To print out the transactions, do `cargo test -- --nocapture`
    println!(
        "{}",
        serde_json::to_string_pretty(&vec![
            SignedTransaction::from(election),
            SignedTransaction::from(vote),
            SignedTransaction::from(secret_share_1),
            SignedTransaction::from(secret_share_2),
            SignedTransaction::from(decryption)
        ])
        .unwrap()
    );

    // TODO: tally!
}

#[test]
fn test_all_elections() {
    for entry in std::fs::read_dir("../test_elections").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            let mut store = MemStore::default();

            let mut paths: Vec<_> = std::fs::read_dir(path)
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            paths.sort_by_key(|dir| dir.path());

            for path in paths {
                let file_bytes = std::fs::read(path.path()).unwrap();

                let txs: Vec<SignedTransaction> = if file_bytes[0] == b"["[0] {
                    serde_json::from_slice(&file_bytes).unwrap()
                } else {
                    vec![SignedTransaction::from_bytes(&file_bytes).unwrap()]
                };

                for tx in txs {
                    tx.validate(&store).unwrap();
                    store.set(tx);
                }
            }
        }
    }
}
