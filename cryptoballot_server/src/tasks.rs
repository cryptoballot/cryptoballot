use cryptid::threshold::KeygenCommitment;
use cryptoballot::*;
use ed25519_dalek::PublicKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek as x25519;

pub fn generate_transactions<S: Store>(
    incoming_tx: &SignedTransaction,
    store: &S,
) -> Result<Vec<SignedTransaction>, Error> {
    match incoming_tx.transaction_type() {
        TransactionType::Election => process_election(store, incoming_tx.clone().into()),
        TransactionType::KeyGenCommitment => {
            process_keygen_commitment(store, incoming_tx.clone().into())
        }
        TransactionType::KeyGenShare => process_keygen_share(store, incoming_tx.clone().into()),

        TransactionType::KeyGenPublicKey => {
            process_keygen_public_key(store, incoming_tx.clone().into())
        }

        TransactionType::VotingEnd => process_voting_end(store, incoming_tx.clone().into()),

        TransactionType::Mix => process_mix(store, incoming_tx.clone().into()),

        TransactionType::PartialDecryption => {
            process_partial_decryption(store, incoming_tx.clone().into())
        }

        _ => Ok(vec![]),
    }
}

fn process_election<S: Store>(
    _store: &S,
    election_tx: ElectionTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    if let Some(trustee) = trustee_from_election(&election_tx, &public_key) {
        // Generate keygen_commitment transactions
        let commit = trustee.keygen_commitment(&secret_key, election_tx.id);
        let x25519_public_key = trustee.x25519_public_key(&secret_key, election_tx.id);
        let commit_tx = KeyGenCommitmentTransaction::new(
            election_tx.id,
            trustee.index,
            trustee.public_key,
            x25519_public_key,
            commit,
        );
        let commit_tx = Signed::sign(&secret_key, commit_tx)?;
        return Ok(vec![commit_tx.into()]);
    }

    Ok(vec![])
}

// On a keygen_commitment transaction, see if we have enough commitments to produce a keygen_share transaction
fn process_keygen_commitment<S: Store>(
    store: &S,
    commit_tx: KeyGenCommitmentTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(commit_tx.election)?.tx;

    if let Some(trustee) = trustee_from_election(&election_tx, &public_key) {
        // Check that we have enough commitment transactions already
        let commit_txs: Vec<KeyGenCommitmentTransaction> = store
            .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
            .into_iter()
            .map(|tx| tx.into())
            .collect();

        if commit_txs.len() == election_tx.trustees.len() {
            let commitments: Vec<(u8, KeygenCommitment)> = commit_txs
                .iter()
                .map(|tx| (tx.trustee_index, tx.commitment.clone()))
                .collect();

            let x25519_public_keys: Vec<(u8, x25519::PublicKey)> = commit_txs
                .into_iter()
                .map(|tx| (tx.trustee_index, tx.x25519_public_key))
                .collect();

            let mut rng: StdRng = SeedableRng::from_entropy();
            let shares = trustee.generate_shares(
                &mut rng,
                &secret_key,
                &x25519_public_keys,
                election_tx.id,
                &commitments,
            );

            let share_tx = KeyGenShareTransaction::new(
                election_tx.id,
                trustee.index,
                trustee.public_key,
                shares,
            );
            let share_tx = Signed::sign(&secret_key, share_tx)?;
            return Ok(vec![share_tx.into()]);
        }
    }

    Ok(vec![])
}

// On keygen_share transaction, check if we have ALL keygens, and if so, generate a public_key (if we are a trustee)
fn process_keygen_share<S: Store>(
    store: &S,
    share_tx: KeyGenShareTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(share_tx.election)?.tx;

    if let Some(trustee) = trustee_from_election(&election_tx, &public_key) {
        // Check that we have enough keygen_tx transactions already
        let share_txs: Vec<KeyGenShareTransaction> = store
            .get_multiple(election_tx.id, TransactionType::KeyGenShare)
            .into_iter()
            .map(|tx| tx.into())
            .collect();

        if share_txs.len() != election_tx.trustees.len() {
            return Ok(vec![]);
        }

        // Get all commitments
        let commitments: Vec<(u8, KeygenCommitment)> = store
            .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
            .into_iter()
            .map(|tx| tx.into())
            .map(|tx: KeyGenCommitmentTransaction| (tx.trustee_index, tx.commitment))
            .collect();

        // Get all x25519 public keys
        let x25519_public_keys: Vec<(u8, x25519::PublicKey)> = store
            .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
            .into_iter()
            .map(|tx| tx.into())
            .map(|tx: KeyGenCommitmentTransaction| (tx.trustee_index, tx.x25519_public_key))
            .collect();

        let shares: Vec<(u8, EncryptedShare)> = share_txs
            .into_iter()
            .map(|tx| {
                (
                    tx.trustee_index,
                    tx.shares.get(&trustee.index).unwrap().clone(),
                )
            })
            .collect();

        let (public_key, public_key_proof) = trustee.generate_public_key(
            &secret_key,
            &x25519_public_keys,
            &commitments,
            &shares,
            election_tx.id,
        )?;

        let pk_tx = KeyGenPublicKeyTransaction::new(
            election_tx.id,
            trustee.index,
            trustee.public_key,
            public_key,
            public_key_proof,
        );
        let secret_key = crate::secret_key();
        let pk_tx = Signed::sign(&secret_key, pk_tx)?;
        return Ok(vec![pk_tx.into()]);
    }

    Ok(vec![])
}

// On keygen_public_key transaction, check if we have ALL trustee public_keys, and if so, generate a encryption_key (if we are election authority)
fn process_keygen_public_key<S: Store>(
    store: &S,
    pk_tx: KeyGenPublicKeyTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(pk_tx.election)?.tx;

    if election_tx.authority_public == public_key {
        // Get all public key transactions
        let pk_txs: Vec<KeyGenPublicKeyTransaction> = store
            .get_multiple(election_tx.id, TransactionType::KeyGenPublicKey)
            .into_iter()
            .map(|tx| tx.into())
            .collect();

        if election_tx.trustees.len() == pk_txs.len() {
            // Generate an encryption_key transaction
            let encryption_key_tx = EncryptionKeyTransaction::new(
                election_tx.id,
                election_tx.authority_public.clone(),
                pk_tx.public_key,
            );
            let encryption_key_tx = Signed::sign(&secret_key, encryption_key_tx)?;
            return Ok(vec![encryption_key_tx.into()]);
        }
    }

    Ok(vec![])
}

// On voting_end transaction, produce either a mix or start decrypting votes (if there is no mix config)
fn process_voting_end<S: Store>(
    store: &S,
    voting_end_tx: VotingEndTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(voting_end_tx.election)?.tx;

    if let Some(trustee) = trustee_from_election(&election_tx, &public_key) {
        // If there's a mix config, produce a mix transaction
        if let Some(_mix_config) = &election_tx.mix_config {
            if trustee.index == 1 {
                // create the mix if we're the first trustee
                // TODO: Handle timeout of the first trustee and we're the second (and so on)
                // TODO: Also handle the situation where WE previously timed out, but we're back online again
                //       In this situation, we go to the "back of the line" to wait our turn again

                // Get the EncryptionKey Transaction
                let encryption_key_tx = EncryptionKeyTransaction::build_id(election_tx.id);
                let encryption_key_tx: EncryptionKeyTransaction =
                    store.get_transaction(encryption_key_tx).unwrap().into();

                // Get all vote transactions
                let vote_txs: Vec<VoteTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::Vote)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                let vote_ids = vote_txs.iter().map(|tx| tx.id).collect();
                let ciphertexts = vote_txs.into_iter().map(|tx| tx.encrypted_vote).collect();

                // TODO: This could be expensive, so don't do it on the consensus thread
                let mut rng = rand::thread_rng();
                let (mixed, proof) = mix(
                    &mut rng,
                    ciphertexts,
                    &encryption_key_tx.encryption_key,
                    trustee.index,
                    0,
                    0,
                    0,
                )?;

                let mix_tx = MixTransaction::new(
                    election_tx.id,
                    None,
                    &trustee,
                    0,
                    0,
                    0,
                    vote_ids,
                    mixed,
                    proof,
                );

                let mix_tx = Signed::sign(&secret_key, mix_tx)?;
                return Ok(vec![mix_tx.into()]);
            }
        } else {
            // If there's no mix config, produce partial decryptions for every vote
            return produce_partials(store, &election_tx, &trustee);
        }
    }

    Ok(vec![])
}

// On mix transaction, produce the next stage in the mix
fn process_mix<S: Store>(
    store: &S,
    mix_tx: MixTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(mix_tx.election_id)?.tx;

    if let Some(trustee) = trustee_from_election(&election_tx, &public_key) {
        // If there's a mix config, produce a mix transaction
        if let Some(_mix_config) = &election_tx.mix_config {
            // If this is the last mix, start producing partial decryptions
            if election_tx.trustees_threshold == mix_tx.mix_index + 1 {
                return produce_partials(store, &election_tx, &trustee);
            }

            // TODO: Handle timeout of an intermediary trustee, and go before it would normally be our turn
            // TODO: Also handle the situation where WE previously timed out, but we're back online again
            //       In this situation, we go to the "back of the line" to wait our turn again

            if trustee.index == mix_tx.mix_index + 2 {
                // Get the EncryptionKey Transaction
                let encryption_key_tx = EncryptionKeyTransaction::build_id(election_tx.id);
                let encryption_key_tx: EncryptionKeyTransaction =
                    store.get_transaction(encryption_key_tx).unwrap().into();

                let vote_ids = mix_tx.vote_ids;
                let ciphertexts = mix_tx.mixed_ciphertexts;

                // TODO: This could be expensive, so don't do it on the consensus thread
                let mut rng = rand::thread_rng();
                let (mixed, proof) = mix(
                    &mut rng,
                    ciphertexts,
                    &encryption_key_tx.encryption_key,
                    trustee.index,
                    mix_tx.mix_index + 1,
                    0,
                    0,
                )?;

                let new_mix_tx = MixTransaction::new(
                    election_tx.id,
                    None,
                    &trustee,
                    mix_tx.mix_index + 1,
                    0,
                    0,
                    vote_ids,
                    mixed,
                    proof,
                );

                let new_mix_tx = Signed::sign(&secret_key, new_mix_tx)?;
                return Ok(vec![new_mix_tx.into()]);
            }
        }
    }

    Ok(vec![])
}

// On PartialDecrytion transaction, check if we have enough partials for a full decryption transaction
// TODO: This needs to be batched, likely goes in a different function, also snouldn't happen on the consensus thread
fn process_partial_decryption<S: Store>(
    store: &S,
    partial_tx: PartialDecryptionTransaction,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // Get the election_tx
    let election_tx = store.get_election(partial_tx.election_id)?.tx;

    if let Some(_trustee) = trustee_from_election(&election_tx, &public_key) {
        // Get partials
        let mut start = election_tx.id().clone();
        start.transaction_type = TransactionType::PartialDecryption;
        let mut unique_info = partial_tx.id.unique_info;
        unique_info[15] = 0;
        start.unique_info = unique_info;

        let mut end = start.clone();
        end.unique_info[15] = 255;

        // TODO: Need some way of partitioning the work between trustee nodes,
        //       while at the same time allowing them to pick up eachother's slack
        //       Alternatively, only the election authority does full decryptions automatically
        //       Alternatively, just do it all with no coordination and let consensus sort it out
        let partial_txs = store.range(start, end);

        if partial_txs.len() >= election_tx.trustees_threshold as usize {
            let partial_txs: Vec<PartialDecryptionTransaction> =
                partial_txs.into_iter().map(|tx| tx.into()).collect();

            // Get the vote
            let vote_tx: VoteTransaction = store
                .get_transaction(partial_tx.upstream_id)
                .unwrap()
                .into();

            // Get public key transactions
            let pubkeys = store.get_multiple(election_tx.id, TransactionType::KeyGenPublicKey);
            let pubkeys: Vec<KeyGenPublicKeyTransaction> =
                pubkeys.into_iter().map(|tx| tx.into()).collect();

            // Fully decrypt the vote
            // TODO: No unwrap, real error
            let decrypted = decrypt_vote(
                &vote_tx.encrypted_vote,
                election_tx.trustees_threshold,
                &election_tx.get_full_trustees(),
                &pubkeys,
                &partial_txs,
            )?;

            let trustee_indexs = partial_txs.iter().map(|tx| tx.trustee_index).collect();

            // Create a vote decryption transaction
            let decrypted_tx = DecryptionTransaction::new(
                election_tx.id,
                vote_tx.id,
                0,
                trustee_indexs,
                decrypted,
            );

            let decrypted_tx = Signed::sign(&secret_key, decrypted_tx)?.into();
            return Ok(vec![decrypted_tx]);
        }
    }

    Ok(vec![])
}

// TODO: Switch to batching
fn produce_partials<S: Store>(
    store: &S,
    election_tx: &ElectionTransaction,
    trustee: &Trustee,
) -> Result<Vec<SignedTransaction>, Error> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // If there's no mix config, produce partial decryptions for every vote
    let mut rng = rand::thread_rng();

    let share_txs: Vec<KeyGenShareTransaction> = store
        .get_multiple(election_tx.id, TransactionType::KeyGenShare)
        .into_iter()
        .map(|tx| tx.into())
        .collect();

    let commit_txs: Vec<KeyGenCommitmentTransaction> = store
        .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
        .into_iter()
        .map(|tx| tx.into())
        .collect();

    let commitments: Vec<(u8, KeygenCommitment)> = commit_txs
        .iter()
        .map(|tx| (tx.trustee_index, tx.commitment.clone()))
        .collect();

    let x25519_public_keys: Vec<(u8, x25519::PublicKey)> = commit_txs
        .into_iter()
        .map(|tx| (tx.trustee_index, tx.x25519_public_key))
        .collect();

    // Get all Shares shared with this trustee
    let shares: Vec<(u8, EncryptedShare)> = share_txs
        .into_iter()
        .map(|tx| {
            (
                tx.trustee_index,
                tx.shares.get(&trustee.index).unwrap().clone(),
            )
        })
        .collect();

    // Get all vote transactions
    let vote_txs = store.get_multiple(election_tx.id, TransactionType::Vote);

    let mut parial_txs = Vec::with_capacity(vote_txs.len());
    for vote_tx in vote_txs {
        let vote_tx: VoteTransaction = vote_tx.into();

        let partial_decrypt = trustee.partial_decrypt(
            &mut rng,
            &secret_key,
            &x25519_public_keys,
            &commitments,
            &shares,
            &vote_tx.encrypted_vote,
            election_tx.id,
        )?;
        let partial_decrypt_tx = PartialDecryptionTransaction::new(
            election_tx.id,
            vote_tx.id,
            0,
            trustee.index,
            public_key,
            partial_decrypt,
        );

        let partial_decrypt_tx = Signed::sign(&secret_key, partial_decrypt_tx)?;
        parial_txs.push(partial_decrypt_tx.into());
    }
    return Ok(parial_txs);
}

fn trustee_from_election(
    election_tx: &ElectionTransaction,
    public_key: &PublicKey,
) -> Option<Trustee> {
    for trustee in election_tx.get_full_trustees() {
        if &trustee.public_key == public_key {
            return Some(trustee);
        }
    }
    None
}
