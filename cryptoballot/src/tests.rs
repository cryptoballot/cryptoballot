use super::*;
use rand::SeedableRng;

#[test]
fn end_to_end_election_no_mix() {
    let mut test_rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut store = MemStore::default();

    // Create election authority public and private key
    let (authority_secret, authority_public) = generate_keypair();

    // Create a ballot
    let ballot_id = "TEST";

    let ballot = Ballot {
        id: ballot_id.to_string(),
        contests: vec![0],
        properties: indexmap::IndexMap::new(),
    };

    let contest = Contest {
        id: "TESTCONTEST".to_string(),
        index: 0,
        contest_type: ContestType::Plurality,
        write_in: true,
        num_winners: 1,
        candidates: vec![],
        properties: indexmap::IndexMap::new(),
    };

    // Create an authenticator
    let (authenticator, authn_secrets) =
        Authenticator::new(256, &vec![ballot_id.to_string()]).unwrap();
    let authn_secret = authn_secrets.get(ballot_id).unwrap();
    let authn_public = authenticator.public_keys.get(ballot_id).unwrap().as_ref();

    // Create 3 trustees
    let (trustee_1, trustee_1_secret) = Trustee::new(1, 3, 2);
    let (trustee_2, trustee_2_secret) = Trustee::new(2, 3, 2);
    let (trustee_3, trustee_3_secret) = Trustee::new(3, 3, 2);

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(authority_public);
    election.ballots = vec![ballot];
    election.contests = vec![contest];
    election.authenticators = vec![authenticator.clone()];
    election.trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];
    election.trustees_threshold = 2;

    // Finalize election transaction by signing it
    let election = Signed::sign(&authority_secret, election).unwrap();

    // Validate the election transaction and store it
    election.validate(&store).unwrap();
    store.set(election.clone().into());

    // Generate keygen_commitment transactions for each trustee
    let x25519_public_1 = trustee_1.x25519_public_key(&trustee_1_secret, election.id);
    let commit_1 = trustee_1.keygen_commitment(&trustee_1_secret, election.id);

    let commit_1_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        x25519_public_1,
        commit_1,
    );
    let commit_1_tx = Signed::sign(&trustee_1_secret, commit_1_tx).unwrap();
    commit_1_tx.validate(&store).unwrap();
    store.set(commit_1_tx.clone().into());

    let x25519_public_2 = trustee_2.x25519_public_key(&trustee_2_secret, election.id);
    let commit_2 = trustee_1.keygen_commitment(&trustee_2_secret, election.id);
    let commit_2_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        x25519_public_2,
        commit_2,
    );
    let commit_2_tx = Signed::sign(&trustee_2_secret, commit_2_tx).unwrap();
    commit_2_tx.validate(&store).unwrap();
    store.set(commit_2_tx.clone().into());

    let x25519_public_3 = trustee_3.x25519_public_key(&trustee_3_secret, election.id);
    let commit_3 = trustee_3.keygen_commitment(&trustee_3_secret, election.id);
    let commit_3_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_3.index,
        trustee_3.public_key,
        x25519_public_3,
        commit_3,
    );
    let commit_3_tx = Signed::sign(&trustee_3_secret, commit_3_tx).unwrap();
    commit_3_tx.validate(&store).unwrap();
    store.set(commit_3_tx.clone().into());

    // Grab cmommitments out of the commitment transactions
    let commitments = [
        (
            commit_1_tx.inner().trustee_index,
            commit_1_tx.inner().commitment.clone(),
        ),
        (
            commit_2_tx.inner().trustee_index,
            commit_2_tx.inner().commitment.clone(),
        ),
        (
            commit_3_tx.inner().trustee_index,
            commit_3_tx.inner().commitment.clone(),
        ),
    ];

    // Grab x25519 public key out of the commitment transactions
    let x25519_public_keys = [
        (
            commit_1_tx.inner().trustee_index,
            commit_1_tx.inner().x25519_public_key.clone(),
        ),
        (
            commit_2_tx.inner().trustee_index,
            commit_2_tx.inner().x25519_public_key.clone(),
        ),
        (
            commit_3_tx.inner().trustee_index,
            commit_3_tx.inner().x25519_public_key.clone(),
        ),
    ];

    // Generate keygen_share transaction for each trustee
    let share_1 = trustee_1.generate_shares(
        &mut test_rng,
        &trustee_1_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_1_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        share_1.clone(),
    );
    let share_1_tx = Signed::sign(&trustee_1_secret, share_1_tx).unwrap();
    share_1_tx.validate(&store).unwrap();
    store.set(share_1_tx.clone().into());

    let share_2 = trustee_2.generate_shares(
        &mut test_rng,
        &trustee_2_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_2_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        share_2.clone(),
    );
    let share_2_tx = Signed::sign(&trustee_2_secret, share_2_tx).unwrap();
    share_2_tx.validate(&store).unwrap();
    store.set(share_2_tx.clone().into());

    let share_3 = trustee_3.generate_shares(
        &mut test_rng,
        &trustee_3_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_3_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_3.index,
        trustee_3.public_key,
        share_3.clone(),
    );
    let share_3_tx = Signed::sign(&trustee_3_secret, share_3_tx).unwrap();
    share_3_tx.validate(&store).unwrap();
    store.set(share_3_tx.clone().into());

    // Generate keygen_public_key transaction for each trustee
    let all_shares = vec![
        (trustee_1.index, &share_1),
        (trustee_2.index, &share_2),
        (trustee_3.index, &share_3),
    ];

    let pk_1_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_1.index).unwrap().clone()))
        .collect();
    let (pk_1, pk_1_proof) = trustee_1
        .generate_public_key(
            &trustee_1_secret,
            &x25519_public_keys,
            &commitments,
            &pk_1_shares,
            election.id,
        )
        .unwrap();
    let pk_1_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        pk_1,
        pk_1_proof,
    );
    let pk_1_tx = Signed::sign(&trustee_1_secret, pk_1_tx).unwrap();
    pk_1_tx.validate(&store).unwrap();
    store.set(pk_1_tx.clone().into());

    let pk_2_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_2.index).unwrap().clone()))
        .collect();
    let (pk_2, pk_2_proof) = trustee_2
        .generate_public_key(
            &trustee_2_secret,
            &x25519_public_keys,
            &commitments,
            &pk_2_shares,
            election.id,
        )
        .unwrap();
    let pk_2_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        pk_2,
        pk_2_proof,
    );
    let pk_2_tx = Signed::sign(&trustee_2_secret, pk_2_tx).unwrap();
    pk_2_tx.validate(&store).unwrap();
    store.set(pk_2_tx.clone().into());

    let pk_3_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_3.index).unwrap().clone()))
        .collect();
    let (pk_3, pk_3_proof) = trustee_3
        .generate_public_key(
            &trustee_3_secret,
            &x25519_public_keys,
            &commitments,
            &pk_3_shares,
            election.id,
        )
        .unwrap();
    let pk_3_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_3.index,
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
    let selection = Selection {
        write_in: false,
        rank: 0,
        selection: "Barak Obama".to_string(),
    };

    // Encrypt the secret vote
    let selections = encrypt_vote(
        &encryption_key_tx.encryption_key,
        vec![selection.clone()],
        &mut test_rng,
    )
    .unwrap();

    let encrypted_vote = EncryptedVote {
        contest_index: 0,
        selections,
    };

    // Generate an empty vote transaction
    let (mut vote, voter_secret) =
        VoteTransaction::new(election.id(), ballot_id.to_string(), vec![encrypted_vote]);

    // Create an auth package and blind it
    let auth_package = AuthPackage::new(election.id(), ballot_id.to_string(), vote.anonymous_key);
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
    let partial_decrypt_1 = trustee_1
        .partial_decrypt(
            &mut test_rng,
            &trustee_1_secret,
            &x25519_public_keys,
            &commitments,
            &pk_1_shares,
            &vote.encrypted_votes[0].selections[0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_1_tx = PartialDecryptionTransaction::new(
        election.id,
        vote.id,
        0,
        trustee_1.index,
        0,
        trustee_1.public_key,
        vec![partial_decrypt_1],
    );
    let partial_decrypt_1_tx = Signed::sign(&trustee_1_secret, partial_decrypt_1_tx).unwrap();
    partial_decrypt_1_tx.validate(&store).unwrap();
    store.set(partial_decrypt_1_tx.clone().into());

    let partial_decrypt_2 = trustee_2
        .partial_decrypt(
            &mut test_rng,
            &trustee_2_secret,
            &x25519_public_keys,
            &commitments,
            &pk_2_shares,
            &vote.encrypted_votes[0].selections[0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_2_tx = PartialDecryptionTransaction::new(
        election.id,
        vote.id,
        0,
        trustee_2.index,
        0,
        trustee_2.public_key,
        vec![partial_decrypt_2],
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
        &vote.encrypted_votes[0].selections,
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
        0,
        vec![trustee_1.index, trustee_2.index],
        decrypted,
    );

    // TODO: Add a decryptor public key to make it meaningful??  It does't really matter..
    let decrypted_tx = Signed::sign(&trustee_1_secret, decrypted_tx).unwrap();
    decrypted_tx.validate(&store).unwrap();
    store.set(decrypted_tx.clone().into());

    // Decrypted vote should match secret vote
    assert_eq!(selection, decrypted_tx.inner().decrypted_vote[0]);

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
fn end_to_end_election_with_mix() {
    let mut test_rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut store = MemStore::default();

    // Create election authority public and private key
    let (authority_secret, authority_public) = generate_keypair();

    // Create a ballot
    let ballot_id = "TEST";

    let ballot = Ballot {
        id: ballot_id.to_string(),
        contests: vec![0],
        properties: indexmap::IndexMap::new(),
    };

    let contest = Contest {
        id: "TESTCONTEST".to_string(),
        index: 0,
        contest_type: ContestType::Plurality,
        write_in: true,
        num_winners: 1,
        candidates: vec![],
        properties: indexmap::IndexMap::new(),
    };

    // Create an authenticator
    let (authenticator, authn_secrets) =
        Authenticator::new(256, &vec![ballot_id.to_string()]).unwrap();
    let authn_secret = authn_secrets.get(ballot_id).unwrap();
    let authn_public = authenticator.public_keys.get(ballot_id).unwrap().as_ref();

    // Create 3 trustees
    let (trustee_1, trustee_1_secret) = Trustee::new(1, 3, 2);
    let (trustee_2, trustee_2_secret) = Trustee::new(2, 3, 2);
    let (trustee_3, trustee_3_secret) = Trustee::new(3, 3, 2);

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(authority_public);
    election.ballots = vec![ballot];
    election.contests = vec![contest];
    election.authenticators = vec![authenticator.clone()];
    election.trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];
    election.trustees_threshold = 2;
    election.mix_config = Some(MixConfig {
        timeout_secs: 600,
        batch_size: None, // No Batching
    });

    // Finalize election transaction by signing it
    let election = Signed::sign(&authority_secret, election).unwrap();

    // Validate the election transaction and store it
    election.validate(&store).unwrap();
    store.set(election.clone().into());

    // Generate keygen_commitment transactions for each trustee
    let x25519_public_1 = trustee_1.x25519_public_key(&trustee_1_secret, election.id);
    let commit_1 = trustee_1.keygen_commitment(&trustee_1_secret, election.id);

    let commit_1_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        x25519_public_1,
        commit_1,
    );
    let commit_1_tx = Signed::sign(&trustee_1_secret, commit_1_tx).unwrap();
    commit_1_tx.validate(&store).unwrap();
    store.set(commit_1_tx.clone().into());

    let x25519_public_2 = trustee_2.x25519_public_key(&trustee_2_secret, election.id);
    let commit_2 = trustee_1.keygen_commitment(&trustee_2_secret, election.id);
    let commit_2_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        x25519_public_2,
        commit_2,
    );
    let commit_2_tx = Signed::sign(&trustee_2_secret, commit_2_tx).unwrap();
    commit_2_tx.validate(&store).unwrap();
    store.set(commit_2_tx.clone().into());

    let x25519_public_3 = trustee_3.x25519_public_key(&trustee_3_secret, election.id);
    let commit_3 = trustee_3.keygen_commitment(&trustee_3_secret, election.id);
    let commit_3_tx = KeyGenCommitmentTransaction::new(
        election.id,
        trustee_3.index,
        trustee_3.public_key,
        x25519_public_3,
        commit_3,
    );
    let commit_3_tx = Signed::sign(&trustee_3_secret, commit_3_tx).unwrap();
    commit_3_tx.validate(&store).unwrap();
    store.set(commit_3_tx.clone().into());

    // Grab cmommitments out of the commitment transactions
    let commitments = [
        (
            commit_1_tx.inner().trustee_index,
            commit_1_tx.inner().commitment.clone(),
        ),
        (
            commit_2_tx.inner().trustee_index,
            commit_2_tx.inner().commitment.clone(),
        ),
        (
            commit_3_tx.inner().trustee_index,
            commit_3_tx.inner().commitment.clone(),
        ),
    ];

    // Grab x25519 public key out of the commitment transactions
    let x25519_public_keys = [
        (
            commit_1_tx.inner().trustee_index,
            commit_1_tx.inner().x25519_public_key.clone(),
        ),
        (
            commit_2_tx.inner().trustee_index,
            commit_2_tx.inner().x25519_public_key.clone(),
        ),
        (
            commit_3_tx.inner().trustee_index,
            commit_3_tx.inner().x25519_public_key.clone(),
        ),
    ];

    // Generate keygen_share transaction for each trustee
    let share_1 = trustee_1.generate_shares(
        &mut test_rng,
        &trustee_1_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_1_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        share_1.clone(),
    );
    let share_1_tx = Signed::sign(&trustee_1_secret, share_1_tx).unwrap();
    share_1_tx.validate(&store).unwrap();
    store.set(share_1_tx.clone().into());

    let share_2 = trustee_2.generate_shares(
        &mut test_rng,
        &trustee_2_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_2_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        share_2.clone(),
    );
    let share_2_tx = Signed::sign(&trustee_2_secret, share_2_tx).unwrap();
    share_2_tx.validate(&store).unwrap();
    store.set(share_2_tx.clone().into());

    let share_3 = trustee_3.generate_shares(
        &mut test_rng,
        &trustee_3_secret,
        &x25519_public_keys,
        election.id,
        &commitments,
    );
    let share_3_tx = KeyGenShareTransaction::new(
        election.id,
        trustee_3.index,
        trustee_3.public_key,
        share_3.clone(),
    );
    let share_3_tx = Signed::sign(&trustee_3_secret, share_3_tx).unwrap();
    share_3_tx.validate(&store).unwrap();
    store.set(share_3_tx.clone().into());

    // Generate keygen_public_key transaction for each trustee
    let all_shares = vec![
        (trustee_1.index, &share_1),
        (trustee_2.index, &share_2),
        (trustee_3.index, &share_3),
    ];

    let pk_1_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_1.index).unwrap().clone()))
        .collect();
    let (pk_1, pk_1_proof) = trustee_1
        .generate_public_key(
            &trustee_1_secret,
            &x25519_public_keys,
            &commitments,
            &pk_1_shares,
            election.id,
        )
        .unwrap();
    let pk_1_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_1.index,
        trustee_1.public_key,
        pk_1,
        pk_1_proof,
    );
    let pk_1_tx = Signed::sign(&trustee_1_secret, pk_1_tx).unwrap();
    pk_1_tx.validate(&store).unwrap();
    store.set(pk_1_tx.clone().into());

    let pk_2_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_2.index).unwrap().clone()))
        .collect();
    let (pk_2, pk_2_proof) = trustee_2
        .generate_public_key(
            &trustee_2_secret,
            &x25519_public_keys,
            &commitments,
            &pk_2_shares,
            election.id,
        )
        .unwrap();
    let pk_2_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_2.index,
        trustee_2.public_key,
        pk_2,
        pk_2_proof,
    );
    let pk_2_tx = Signed::sign(&trustee_2_secret, pk_2_tx).unwrap();
    pk_2_tx.validate(&store).unwrap();
    store.set(pk_2_tx.clone().into());

    let pk_3_shares: Vec<(u8, EncryptedShare)> = all_shares
        .iter()
        .map(|m| (m.0, m.1.get(&trustee_3.index).unwrap().clone()))
        .collect();
    let (pk_3, pk_3_proof) = trustee_3
        .generate_public_key(
            &trustee_3_secret,
            &x25519_public_keys,
            &commitments,
            &pk_3_shares,
            election.id,
        )
        .unwrap();
    let pk_3_tx = KeyGenPublicKeyTransaction::new(
        election.id,
        trustee_3.index,
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
    let selection = Selection {
        write_in: false,
        rank: 0,
        selection: "Barak Obama".to_string(),
    };

    // Encrypt the secret vote
    let selections = encrypt_vote(
        &encryption_key_tx.encryption_key,
        vec![selection.clone()],
        &mut test_rng,
    )
    .unwrap();

    let encrypted_vote = EncryptedVote {
        contest_index: 0,
        selections,
    };

    // Generate an empty vote transaction
    let (mut vote, voter_secret) =
        VoteTransaction::new(election.id(), ballot_id.to_string(), vec![encrypted_vote]);

    // Create an auth package and blind it
    let auth_package = AuthPackage::new(election.id(), ballot_id.to_string(), vote.anonymous_key);
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

    // Generate an second vote transaction

    // Create a 2nd vote transaction
    let selection_2 = Selection {
        write_in: false,
        rank: 0,
        selection: "Santa".to_string(),
    };

    // Encrypt the secret vote
    let selections_2_encrypted = encrypt_vote(
        &encryption_key_tx.encryption_key,
        vec![selection_2.clone()],
        &mut test_rng,
    )
    .unwrap();

    let encrypted_vote_2 = EncryptedVote {
        contest_index: 0,
        selections: selections_2_encrypted,
    };

    let (mut vote_2, voter_secret_2) =
        VoteTransaction::new(election.id(), ballot_id.to_string(), vec![encrypted_vote_2]);

    // Create an auth package and blind it
    let auth_package_2 =
        AuthPackage::new(election.id(), ballot_id.to_string(), vote_2.anonymous_key);
    let (blinded_auth_package_2, unblinder_2) = auth_package_2.blind(&authn_public);

    // Authenticate the voter (for a real election the voter would pass additional auth info)
    let authentication_2 = authenticator.authenticate(&authn_secret, &blinded_auth_package_2);
    let authentication_2 = authentication_2.unblind(&authn_public, unblinder_2);

    // Attach the authentication to the vote
    vote_2.authentication.push(authentication_2);

    // Sign and seal the vote transaction
    let vote_2 = Signed::sign(&voter_secret_2, vote_2).unwrap();

    // Validate the vote transaction and store it
    vote_2.validate(&store).unwrap();
    store.set(vote_2.clone().into());

    // Voting is over!
    // ---------------

    // Generate VotingEnd transaction to mark the end of voting
    let voting_end_tx = VotingEndTransaction::new(election.id, election.authority_public);
    let voting_end_tx = Signed::sign(&authority_secret, voting_end_tx).unwrap();
    voting_end_tx.validate(&store).unwrap();
    store.set(voting_end_tx.clone().into());

    let mut votes = vec![vote.clone(), vote_2.clone()];
    votes.sort_by(|v1, v2| v1.id().cmp(&v2.id()));

    let vote_ciphertexts = votes
        .iter()
        .map(|v| v.tx.encrypted_votes[0].selections.clone())
        .collect();

    let vote_ids = votes.iter().map(|v| v.id()).collect();

    // Generate the first mix transaction
    let (shuffle_1, proof) = mix(
        &mut test_rng,
        vote_ciphertexts,
        &encryption_key_tx.encryption_key,
        trustee_1.index,
        0,
        0,
        0,
    )
    .unwrap();

    let shuffle_tx_1 = MixTransaction::new(
        election.id,
        None,
        &trustee_1,
        0,
        0,
        0,
        vote_ids,
        shuffle_1,
        proof,
    );
    let shuffle_tx_1 = Signed::sign(&trustee_1_secret, shuffle_tx_1).unwrap();
    shuffle_tx_1.validate(&store).unwrap();
    store.set(shuffle_tx_1.clone().into());

    // Generate the second mix transaction
    let (shuffle_2, proof) = mix(
        &mut test_rng,
        shuffle_tx_1.tx.mixed_ciphertexts.clone(),
        &encryption_key_tx.encryption_key,
        trustee_2.index,
        1,
        0,
        0,
    )
    .unwrap();

    let shuffle_tx_2 = MixTransaction::new(
        election.id,
        Some(shuffle_tx_1.id()),
        &trustee_2,
        1,
        0,
        0,
        shuffle_tx_1.vote_ids.clone(),
        shuffle_2,
        proof,
    );
    let shuffle_tx_2 = Signed::sign(&trustee_2_secret, shuffle_tx_2).unwrap();
    shuffle_tx_2.validate(&store).unwrap();
    store.set(shuffle_tx_2.clone().into());

    // Generate a partial-decryption transactions
    let upstream_index = 0;
    let partial_decrypt_1_1 = trustee_1
        .partial_decrypt(
            &mut test_rng,
            &trustee_1_secret,
            &x25519_public_keys,
            &commitments,
            &pk_1_shares,
            &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize][0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_1_1_tx = PartialDecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        upstream_index,
        trustee_1.index,
        0,
        trustee_1.public_key,
        vec![partial_decrypt_1_1],
    );
    let partial_decrypt_1_1_tx = Signed::sign(&trustee_1_secret, partial_decrypt_1_1_tx).unwrap();
    partial_decrypt_1_1_tx.validate(&store).unwrap();
    store.set(partial_decrypt_1_1_tx.clone().into());

    let partial_decrypt_1_2 = trustee_2
        .partial_decrypt(
            &mut test_rng,
            &trustee_2_secret,
            &x25519_public_keys,
            &commitments,
            &pk_2_shares,
            &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize][0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_1_2_tx = PartialDecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        upstream_index,
        trustee_2.index,
        0,
        trustee_2.public_key,
        vec![partial_decrypt_1_2],
    );
    let partial_decrypt_1_2_tx = Signed::sign(&trustee_2_secret, partial_decrypt_1_2_tx).unwrap();
    partial_decrypt_1_2_tx.validate(&store).unwrap();
    store.set(partial_decrypt_1_2_tx.clone().into());

    let partials = vec![
        partial_decrypt_1_1_tx.tx.clone(),
        partial_decrypt_1_2_tx.tx.clone(),
    ];
    let pubkeys = vec![pk_1_tx.tx.clone(), pk_2_tx.tx.clone(), pk_3_tx.tx.clone()];

    // Fully decrypt the vote
    let decrypted_1 = decrypt_vote(
        &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize],
        election.trustees_threshold,
        &election.trustees,
        &pubkeys,
        &partials,
    )
    .unwrap();

    // Create a vote decryption transaction
    let decrypted_tx_1 = DecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        0,
        upstream_index,
        vec![trustee_1.index, trustee_2.index],
        decrypted_1,
    );

    // TODO: Add a decryptor public key to make it meaningful??  It does't really matter..
    // TODO: Do this and require it to be a trustee
    let decrypted_tx_1 = Signed::sign(&trustee_1_secret, decrypted_tx_1).unwrap();
    decrypted_tx_1.validate(&store).unwrap();
    store.set(decrypted_tx_1.clone().into());

    // Generate a second partial-decryption transactions
    let upstream_index = 1;
    let partial_decrypt_2_1 = trustee_1
        .partial_decrypt(
            &mut test_rng,
            &trustee_1_secret,
            &x25519_public_keys,
            &commitments,
            &pk_1_shares,
            &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize][0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_2_1_tx = PartialDecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        upstream_index,
        trustee_1.index,
        0,
        trustee_1.public_key,
        vec![partial_decrypt_2_1],
    );
    let partial_decrypt_2_1_tx = Signed::sign(&trustee_1_secret, partial_decrypt_2_1_tx).unwrap();
    partial_decrypt_2_1_tx.validate(&store).unwrap();
    store.set(partial_decrypt_2_1_tx.clone().into());

    let partial_decrypt_2_2 = trustee_2
        .partial_decrypt(
            &mut test_rng,
            &trustee_2_secret,
            &x25519_public_keys,
            &commitments,
            &pk_2_shares,
            &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize][0],
            election.id,
        )
        .unwrap();
    let partial_decrypt_2_2_tx = PartialDecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        upstream_index,
        trustee_2.index,
        0,
        trustee_2.public_key,
        vec![partial_decrypt_2_2],
    );
    let partial_decrypt_2_2_tx = Signed::sign(&trustee_2_secret, partial_decrypt_2_2_tx).unwrap();
    partial_decrypt_2_2_tx.validate(&store).unwrap();
    store.set(partial_decrypt_2_2_tx.clone().into());

    let partials = vec![
        partial_decrypt_2_1_tx.tx.clone(),
        partial_decrypt_2_2_tx.tx.clone(),
    ];
    let pubkeys = vec![pk_1_tx.tx.clone(), pk_2_tx.tx.clone(), pk_3_tx.tx.clone()];

    // Fully decrypt the vote
    let decrypted_2 = decrypt_vote(
        &shuffle_tx_2.mixed_ciphertexts[upstream_index as usize],
        election.trustees_threshold,
        &election.trustees,
        &pubkeys,
        &partials,
    )
    .unwrap();

    // Create a vote decryption transaction
    let decrypted_tx_2 = DecryptionTransaction::new(
        election.id,
        shuffle_tx_2.id(),
        0,
        upstream_index,
        vec![trustee_1.index, trustee_2.index],
        decrypted_2,
    );

    // TODO: Add a decryptor public key to make it meaningful??  It does't really matter..
    // TODO: Do this and require it to be a trustee
    let decrypted_tx_2 = Signed::sign(&trustee_1_secret, decrypted_tx_2).unwrap();
    decrypted_tx_2.validate(&store).unwrap();
    store.set(decrypted_tx_2.clone().into());

    // Decrypted votes should match secret votes, but unknown order
    let secret_votes = vec![selection, selection_2];
    assert!(
        vec![
            decrypted_tx_1.inner().decrypted_vote[0].clone(),
            decrypted_tx_2.inner().decrypted_vote[0].clone()
        ] == secret_votes
            || vec![
                decrypted_tx_2.inner().decrypted_vote[0].clone(),
                decrypted_tx_1.inner().decrypted_vote[0].clone()
            ] == secret_votes
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
            SignedTransaction::from(vote_2),
            SignedTransaction::from(voting_end_tx),
            SignedTransaction::from(shuffle_tx_1),
            SignedTransaction::from(shuffle_tx_2),
            SignedTransaction::from(partial_decrypt_1_1_tx),
            SignedTransaction::from(partial_decrypt_1_2_tx),
            SignedTransaction::from(partial_decrypt_2_1_tx),
            SignedTransaction::from(partial_decrypt_2_2_tx),
            SignedTransaction::from(decrypted_tx_1),
            SignedTransaction::from(decrypted_tx_2),
        ])
        .unwrap()
    );
}

#[test]
fn test_all_elections() {
    // TODO: When format is stable uncomment
    //return;
    //#[allow(unreachable_code)]

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
