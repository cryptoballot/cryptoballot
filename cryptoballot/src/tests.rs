use super::*;
use rand::SeedableRng;
use uuid::Uuid;

#[test]
fn end_to_end_election() {
    let mut test_rng = rand::rngs::StdRng::from_seed([0u8; 32]);
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
    let (trustee_1, trustee_1_secret) = Trustee::new(1, 3, 2);
    let (trustee_2, trustee_2_secret) = Trustee::new(2, 3, 2);
    let (trustee_3, trustee_3_secret) = Trustee::new(3, 3, 2);

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(authority_public);
    election.ballots = vec![ballot_id];
    election.authenticators = vec![authenticator.clone()];
    election.trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];
    election.trustees_threshold = 2;

    // Finalize election transaction by signing it
    let election = Signed::sign(&authority_secret, election).unwrap();

    // Validate the election transaction and store it
    election.validate(&store).unwrap();
    store.set(election.clone().into());

    // Generate keygen_commitment transactions for each trustee
    let commit_1 = trustee_1.keygen_commitment(&trustee_1_secret);
    let commit_1_tx =
        KeyGenCommitmentTransaction::new(election.id, trustee_1.id, trustee_1.public_key, commit_1);
    let commit_1_tx = Signed::sign(&trustee_1_secret, commit_1_tx).unwrap();
    commit_1_tx.validate(&store).unwrap();
    store.set(commit_1_tx.clone().into());

    let commit_2 = trustee_1.keygen_commitment(&trustee_2_secret);
    let commit_2_tx =
        KeyGenCommitmentTransaction::new(election.id, trustee_2.id, trustee_2.public_key, commit_2);
    let commit_2_tx = Signed::sign(&trustee_2_secret, commit_2_tx).unwrap();
    commit_2_tx.validate(&store).unwrap();
    store.set(commit_2_tx.clone().into());

    let commit_3 = trustee_3.keygen_commitment(&trustee_3_secret);
    let commit_3_tx =
        KeyGenCommitmentTransaction::new(election.id, trustee_3.id, trustee_3.public_key, commit_3);
    let commit_3_tx = Signed::sign(&trustee_3_secret, commit_3_tx).unwrap();
    commit_3_tx.validate(&store).unwrap();
    store.set(commit_3_tx.clone().into());

    // Grab cmommitments out of the commitment transactions
    let commitments = [
        (
            commit_1_tx.inner().trustee_id,
            commit_1_tx.inner().commitment.clone(),
        ),
        (
            commit_2_tx.inner().trustee_id,
            commit_2_tx.inner().commitment.clone(),
        ),
        (
            commit_3_tx.inner().trustee_id,
            commit_3_tx.inner().commitment.clone(),
        ),
    ];

    // Generate keygen_share transaction for each trustee
    let share_1 = trustee_1.generate_shares(
        &mut test_rng,
        &trustee_1_secret,
        &election.trustees,
        &commitments,
    );
    let share_1_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_1.id,
        trustee_1.public_key,
        share_1.clone(),
    );
    let share_1_tx = Signed::sign(&trustee_1_secret, share_1_tx).unwrap();
    share_1_tx.validate(&store).unwrap();
    store.set(share_1_tx.clone().into());

    let share_2 = trustee_2.generate_shares(
        &mut test_rng,
        &trustee_2_secret,
        &election.trustees,
        &commitments,
    );
    let share_2_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_2.id,
        trustee_2.public_key,
        share_2.clone(),
    );
    let share_2_tx = Signed::sign(&trustee_2_secret, share_2_tx).unwrap();
    share_2_tx.validate(&store).unwrap();
    store.set(share_2_tx.clone().into());

    let share_3 = trustee_3.generate_shares(
        &mut test_rng,
        &trustee_3_secret,
        &election.trustees,
        &commitments,
    );
    let share_3_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_3.id,
        trustee_3.public_key,
        share_3.clone(),
    );
    let share_3_tx = Signed::sign(&trustee_3_secret, share_3_tx).unwrap();
    share_3_tx.validate(&store).unwrap();
    store.set(share_3_tx.clone().into());

    // Generate keygen_public_key transaction for each trustee
    let all_shares = vec![
        (trustee_1.id, &share_1),
        (trustee_2.id, &share_2),
        (trustee_3.id, &share_3),
    ];

    let pk_1_shares: Vec<(Uuid, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_1.id).unwrap().clone()))
        .collect();
    let (pk_1, pk_1_proof) = trustee_1.generate_public_key(
        &trustee_1_secret,
        &election.trustees,
        &commitments,
        &pk_1_shares,
    );
    let pk_1_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_1.id,
        trustee_1.public_key,
        pk_1,
        pk_1_proof,
    );
    let pk_1_tx = Signed::sign(&trustee_1_secret, pk_1_tx).unwrap();
    pk_1_tx.validate(&store).unwrap();
    store.set(pk_1_tx.clone().into());

    let pk_2_shares: Vec<(Uuid, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_2.id).unwrap().clone()))
        .collect();
    let (pk_2, pk_2_proof) = trustee_2.generate_public_key(
        &trustee_2_secret,
        &election.trustees,
        &commitments,
        &pk_2_shares,
    );
    let pk_2_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_2.id,
        trustee_2.public_key,
        pk_2,
        pk_2_proof,
    );
    let pk_2_tx = Signed::sign(&trustee_2_secret, pk_2_tx).unwrap();
    pk_2_tx.validate(&store).unwrap();
    store.set(pk_2_tx.clone().into());

    let pk_3_shares: Vec<(Uuid, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_3.id).unwrap().clone()))
        .collect();
    let (pk_3, pk_3_proof) = trustee_3.generate_public_key(
        &trustee_3_secret,
        &election.trustees,
        &commitments,
        &pk_3_shares,
    );
    let pk_3_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_3.id,
        trustee_3.public_key,
        pk_3,
        pk_3_proof,
    );
    let pk_3_tx = Signed::sign(&trustee_3_secret, pk_3_tx).unwrap();
    pk_3_tx.validate(&store).unwrap();
    store.set(pk_3_tx.clone().into());

    // Generate an encryption_key transaction
    let encryption_key_tx =
        EncryptionKeyTransaction::new(election.id, authority_public, pk_1_tx.inner().public_key);
    let encryption_key_tx = Signed::sign(&authority_secret, encryption_key_tx).unwrap();
    encryption_key_tx.validate(&store).unwrap();
    store.set(encryption_key_tx.clone().into());

    // Create a vote transaction
    let secret_vote = "Barak Obama";

    // Encrypt the secret vote
    let encrypted_vote = encrypt_vote(
        &encryption_key_tx.encryption_key,
        secret_vote.as_bytes(),
        &mut test_rng,
    )
    .unwrap();

    // Generate an empty vote transaction
    let (mut vote, voter_secret) = VoteTransaction::new(election.id(), ballot_id, encrypted_vote);

    // Create an auth package and blind it
    let auth_package = AuthPackage::new(election.id(), ballot_id, vote.anonymous_key);
    let (blinded_auth_package, unblinder) = auth_package.blind(&authn_public);

    // Authenticate the voter (for a real election the voter would pass additional auth info)
    let authentication = authenticator.authenticate(&authn_secret, &blinded_auth_package);
    let authentication = authentication.unblind(&authn_public, unblinder);

    // Attach the authentication to the vote
    vote.authentication.push(authentication);

    // Sign and seal the vote transaction
    let vote = Signed::sign(&voter_secret, vote).unwrap();

    // Validate the vote transaction and store it
    vote.validate(&store).unwrap();
    store.set(vote.clone().into());

    // Voting is over!
    // ---------------

    // Generate VotingEnd transaction to mark the end of voting
    let voting_end_tx = VotingEndTransaction::new(election.id, election.authority_public);
    let voting_end_tx = Signed::sign(&authority_secret, voting_end_tx).unwrap();
    voting_end_tx.validate(&store).unwrap();
    store.set(voting_end_tx.clone().into());

    // Generate a partial-decryption transactions
    let partial_decrypt_1 = trustee_1.partial_decrypt(
        &mut test_rng,
        &trustee_1_secret,
        &election.trustees,
        &commitments,
        &pk_1_shares,
        &vote.encrypted_vote,
    );
    let partial_decrypt_1_tx = PartialDecryptionTransaction::new(
        election.id,
        vote.id,
        0,
        trustee_1.id,
        trustee_1.index,
        trustee_1.public_key,
        partial_decrypt_1,
    );
    let partial_decrypt_1_tx = Signed::sign(&trustee_1_secret, partial_decrypt_1_tx).unwrap();
    partial_decrypt_1_tx.validate(&store).unwrap();
    store.set(partial_decrypt_1_tx.clone().into());

    let partial_decrypt_2 = trustee_2.partial_decrypt(
        &mut test_rng,
        &trustee_2_secret,
        &election.trustees,
        &commitments,
        &pk_2_shares,
        &vote.encrypted_vote,
    );
    let partial_decrypt_2_tx = PartialDecryptionTransaction::new(
        election.id,
        vote.id,
        0,
        trustee_2.id,
        trustee_2.index,
        trustee_2.public_key,
        partial_decrypt_2,
    );
    let partial_decrypt_2_tx = Signed::sign(&trustee_2_secret, partial_decrypt_2_tx).unwrap();
    partial_decrypt_2_tx.validate(&store).unwrap();
    store.set(partial_decrypt_2_tx.clone().into());

    let partials = vec![
        partial_decrypt_1_tx.tx.clone(),
        partial_decrypt_2_tx.tx.clone(),
    ];
    let pubkeys = vec![pk_1_tx.tx.clone(), pk_2_tx.tx.clone(), pk_3_tx.tx.clone()];

    // Fully decrypt the vote
    let decrypted = decrypt_vote(
        &vote.encrypted_vote,
        election.trustees_threshold,
        &election.trustees,
        &pubkeys,
        &partials,
    )
    .unwrap();

    // Create a vote decryption transaction
    let decrypted_tx = DecryptionTransaction::new(
        election.id,
        vote.id,
        0,
        vec![trustee_1.id, trustee_2.id],
        decrypted,
    );

    // TODO: Add a decryptor public key to make it meaningful??  It does't really matter..
    let decrypted_tx = Signed::sign(&trustee_1_secret, decrypted_tx).unwrap();
    decrypted_tx.validate(&store).unwrap();
    store.set(decrypted_tx.clone().into());

    // Decrypted vote should match secret vote
    assert_eq!(
        secret_vote.as_bytes().to_vec(),
        decrypted_tx.inner().decrypted_vote
    );

    // Dump out the votes to JSON
    // To print out the transactions, do `cargo test -- --nocapture`
    println!(
        "{}",
        serde_json::to_string_pretty(&vec![
            SignedTransaction::from(election),
            SignedTransaction::from(commit_1_tx),
            SignedTransaction::from(commit_2_tx),
            SignedTransaction::from(commit_3_tx),
            SignedTransaction::from(share_1_tx),
            SignedTransaction::from(share_2_tx),
            SignedTransaction::from(share_3_tx),
            SignedTransaction::from(pk_1_tx),
            SignedTransaction::from(pk_2_tx),
            SignedTransaction::from(pk_3_tx),
            SignedTransaction::from(encryption_key_tx),
            SignedTransaction::from(vote),
            SignedTransaction::from(voting_end_tx),
            SignedTransaction::from(partial_decrypt_1_tx),
            SignedTransaction::from(partial_decrypt_2_tx),
            SignedTransaction::from(decrypted_tx),
        ])
        .unwrap()
    );
}

#[test]
fn test_all_elections() {
    // TODO: When format is stable uncomment
    return;
    #[allow(unreachable_code)]
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
                if path.path().is_dir() {
                    continue;
                }

                let file_bytes = std::fs::read(path.path()).unwrap();

                let txs: Vec<SignedTransaction> = if file_bytes[0] == b"["[0] {
                    serde_json::from_slice(&file_bytes).unwrap()
                } else {
                    vec![SignedTransaction::from_bytes(&file_bytes).unwrap()]
                };

                for tx in txs {
                    if let Err(e) = tx.validate(&store) {
                        panic!(
                            "Failed to validate {} trancaction {}. Error: {}",
                            tx.transaction_type(),
                            tx.id(),
                            e
                        );
                    }
                    store.set(tx);
                }
            }
        }
    }
}
