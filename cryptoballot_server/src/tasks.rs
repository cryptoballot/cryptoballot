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
        for trustee in &election_tx.trustees {
            if trustee.public_key == public_key {
                // Generate keygen_commitment transactions
                let mut trustee = trustee.clone();
                trustee.num_trustees = election_tx.trustees.len();
                trustee.threshold = election_tx.trustees_threshold;
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

        for trustee in &election_tx.trustees {
            if trustee.public_key == public_key {
                // Check that we have enough commitment transactions already
                let commit_txs: Vec<KeyGenCommitmentTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                if commit_txs.len() == election_tx.trustees.len() {
                    // We have enough commitments, generate a keyshare transactions
                    let mut trustee = trustee.clone();
                    trustee.num_trustees = election_tx.trustees.len();
                    trustee.threshold = election_tx.trustees_threshold;

                    let commitments: Vec<(Uuid, KeygenCommitment)> = commit_txs
                        .into_iter()
                        .map(|tx| (tx.trustee_id, tx.commitment))
                        .collect();

                    let mut rng: StdRng = SeedableRng::from_entropy();
                    let shares = trustee.generate_shares(
                        &mut rng,
                        &secret_key,
                        &election_tx.trustees,
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

        for trustee in &election_tx.trustees {
            if trustee.public_key == public_key {
                // Check that we have enough keygen_tx transactions already
                let share_txs: Vec<KeyGenShareTransaction> = store
                    .get_multiple(election_tx.id, TransactionType::KeyGenShare)
                    .into_iter()
                    .map(|tx| tx.into())
                    .collect();

                if share_txs.len() == election_tx.trustees.len() {
                    // We have enough shares, generate a public_key transactions
                    let mut trustee = trustee.clone();
                    trustee.num_trustees = election_tx.trustees.len();
                    trustee.threshold = election_tx.trustees_threshold;

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
                        &election_tx.trustees,
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
        let election_tx: ElectionTransaction = incoming_tx.clone().into(); // TODO: asRef

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

    // TODO: On an VotingEnd transaction start decrypting votes
    // TODO: On a PartialDecrytion transaction see if we can do a full decryption

    // Nothing
    return vec![];
}
