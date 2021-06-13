use cryptid::threshold::KeygenCommitment;
use cryptoballot::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

pub fn generate_transactions<S: Store>(
    incoming_tx: &SignedTransaction,
    store: &S,
) -> Vec<SignedTransaction> {
    let public_key = crate::public_key();
    let secret_key = crate::secret_key();

    // On an election tx, check if we are a trustee, and if so, generate a commitment transaction
    if incoming_tx.transaction_type() == TransactionType::Election {
        let election_tx: ElectionTransaction = incoming_tx.clone().into(); // TODO: asRef
        for trustee in &election_tx.get_full_trustees() {
            if trustee.public_key == public_key {
                // Generate keygen_commitment transactions
                let commit = trustee.keygen_commitment(&secret_key);
                let commit_tx = KeyGenCommitmentTransaction::new(
                    election_tx.id,
                    trustee.id,
                    trustee.public_key,
                    commit,
                );
                let commit_tx = Signed::sign(&secret_key, commit_tx).unwrap();
                return vec![commit_tx.into()];
            }
        }
    }

    // On commitment transaction, check if we have ALL commitments, and if so, generate a share (if we are a trustee)
    if incoming_tx.transaction_type() == TransactionType::KeyGenCommitment {
        let commit_tx: KeyGenCommitmentTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction =
            store.get_transaction(commit_tx.election).unwrap().into();

        for trustee in &election_tx.get_full_trustees() {
            if trustee.public_key == public_key {
                // Check that we have enough commitment transactions already
                let commit_txs: Vec<KeyGenCommitmentTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                if commit_txs.len() == election_tx.trustees.len() {
                    let commitments: Vec<(Uuid, KeygenCommitment)> = commit_txs
                        .into_iter()
                        .map(|tx| (tx.trustee_id, tx.commitment))
                        .collect();

                    let mut rng: StdRng = SeedableRng::from_entropy();
                    let shares = trustee.generate_shares(
                        &mut rng,
                        &secret_key,
                        &election_tx.get_full_trustees(),
                        &commitments,
                    );

                    let share_tx = KeyGenShareTransaction::new(
                        election_tx.id,
                        trustee.id,
                        trustee.public_key,
                        shares,
                    );
                    let share_tx = Signed::sign(&secret_key, share_tx).unwrap();
                    return vec![share_tx.into()];
                }
            }
        }
    }

    // On keygen transaction, check if we have ALL keygens, and if so, generate a public_key (if we are a trustee)
    if incoming_tx.transaction_type() == TransactionType::KeyGenShare {
        let keygen_tx: KeyGenShareTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction =
            store.get_transaction(keygen_tx.election).unwrap().into();

        for trustee in &election_tx.get_full_trustees() {
            if trustee.public_key == public_key {
                // Check that we have enough keygen_tx transactions already
                let share_txs: Vec<KeyGenShareTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenShare)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                if share_txs.len() == election_tx.trustees.len() {
                    // Get all commitments
                    let commitments: Vec<(Uuid, KeygenCommitment)> = store
                        .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                        .into_iter()
                        .map(|tx| tx.into())
                        .map(|tx: KeyGenCommitmentTransaction| (tx.trustee_id, tx.commitment))
                        .collect();

                    let shares: Vec<(Uuid, EncryptedShare)> = share_txs
                        .into_iter()
                        .map(|tx| (tx.trustee_id, tx.shares.get(&trustee.id).unwrap().clone()))
                        .collect();

                    let (public_key, public_key_proof) = trustee.generate_public_key(
                        &secret_key,
                        &election_tx.get_full_trustees(),
                        &commitments,
                        &shares,
                    );

                    let pk_tx = KeyGenPublicKeyTransaction::new(
                        election_tx.id,
                        trustee.id,
                        trustee.public_key,
                        public_key,
                        public_key_proof,
                    );
                    let secret_key = crate::secret_key();
                    let pk_tx = Signed::sign(&secret_key, pk_tx).unwrap();
                    return vec![pk_tx.into()];
                }
            }
        }
    }

    // On public_key transaction, check if we have ALL public-keys, and if so, generate a encryption_key transaction (if we are the election authority)
    if incoming_tx.transaction_type() == TransactionType::KeyGenPublicKey {
        let keygen_public_key: KeyGenPublicKeyTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = store
            .get_transaction(keygen_public_key.election)
            .unwrap()
            .into();

        if election_tx.authority_public == public_key {
            let pk_tx: KeyGenPublicKeyTransaction = incoming_tx.clone().into(); // TODO: asRef

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
                let encryption_key_tx = Signed::sign(&secret_key, encryption_key_tx).unwrap();
                return vec![encryption_key_tx.into()];
            }
        }
    }

    // On voting_end transaction, do partial-decryption transactions for all votes
    // TODO: This needs to be batched, likely goes in a different function, also snouldn't happen on the consensus thread
    if incoming_tx.transaction_type() == TransactionType::VotingEnd {
        let voting_end_tx: VotingEndTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = store
            .get_transaction(voting_end_tx.election)
            .unwrap()
            .into();

        let mut rng = rand::thread_rng();

        for trustee in &election_tx.get_full_trustees() {
            if trustee.public_key == public_key {
                let share_txs: Vec<KeyGenShareTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenShare)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                // Get all commitments
                let commitments: Vec<(Uuid, KeygenCommitment)> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                    .into_iter()
                    .map(|tx| tx.into())
                    .map(|tx: KeyGenCommitmentTransaction| (tx.trustee_id, tx.commitment))
                    .collect();

                // Get all Shares shared with this trustee
                let shares: Vec<(Uuid, EncryptedShare)> = share_txs
                    .into_iter()
                    .map(|tx| (tx.trustee_id, tx.shares.get(&trustee.id).unwrap().clone()))
                    .collect();

                // Get all vote transactions
                let vote_txs = store.get_multiple(voting_end_tx.election, TransactionType::Vote);

                let mut parial_txs = Vec::with_capacity(vote_txs.len());
                for vote_tx in vote_txs {
                    let vote_tx: VoteTransaction = vote_tx.into();

                    let partial_decrypt = trustee.partial_decrypt(
                        &mut rng,
                        &secret_key,
                        &election_tx.get_full_trustees(),
                        &commitments,
                        &shares,
                        &vote_tx.encrypted_vote,
                    );
                    let partial_decrypt_tx = PartialDecryptionTransaction::new(
                        election_tx.id,
                        vote_tx.id,
                        0,
                        trustee.id,
                        trustee.index,
                        public_key,
                        partial_decrypt,
                    );

                    let partial_decrypt_tx = Signed::sign(&secret_key, partial_decrypt_tx).unwrap();
                    parial_txs.push(partial_decrypt_tx.into());
                }
                return parial_txs;
            }
        }
    }

    // On PartialDecrytion transaction, check if we have enough partials for a full decryption transaction
    // TODO: This needs to be batched, likely goes in a different function, also snouldn't happen on the consensus thread
    if incoming_tx.transaction_type() == TransactionType::PartialDecryption {
        let partial_tx: PartialDecryptionTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = store
            .get_transaction(partial_tx.election_id)
            .unwrap()
            .into();

        // Get partials
        let mut start = election_tx.id().clone();
        start.transaction_type = TransactionType::PartialDecryption;
        let mut unique_id = partial_tx.id.unique_id.unwrap();
        unique_id[15] = 0;
        start.unique_id = Some(unique_id.clone());

        let mut end = start.clone();
        unique_id[15] = 255;
        end.unique_id = Some(unique_id);

        // TODO: Need some way of partitioning the work between trustee nodes,
        //       while at the same time allowing them to pick up eachother's slack
        //       Alternatively, only the election authority does full decryptions automatically
        //       Alternatively, just do it all with no coordination and let consensus sort it out
        let partial_txs = store.range(start, end);

        if partial_txs.len() >= election_tx.trustees_threshold {
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
            )
            .unwrap();

            let trustee_ids = partial_txs.iter().map(|tx| tx.trustee_id).collect();

            // Create a vote decryption transaction
            let decrypted_tx =
                DecryptionTransaction::new(election_tx.id, vote_tx.id, trustee_ids, decrypted);

            let decrypted_tx = Signed::sign(&secret_key, decrypted_tx).unwrap().into();
            return vec![decrypted_tx];
        }
    }

    // Nothing
    return vec![];
}
