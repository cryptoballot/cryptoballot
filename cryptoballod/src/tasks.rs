use crate::CONFIG;
use crate::MEM_STORE;
use cryptid::threshold::KeygenCommitment;
use cryptoballot::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

pub async fn run_tasks(incoming_tx: &SignedTransaction, db: &crate::Db) {
    // On an election tx, check if we are a trustee, and if so, generate a commitment transaction
    if incoming_tx.transaction_type() == TransactionType::Election {
        let election_tx: ElectionTransaction = incoming_tx.clone().into(); // TODO: asRef
        for trustee in &election_tx.trustees {
            if trustee.public_key == CONFIG.public_key {
                // Generate keygen_commitment transactions
                let mut trustee = trustee.clone();
                trustee.num_trustees = election_tx.trustees.len();
                trustee.threshold = election_tx.trustees_threshold;
                let commit = trustee.keygen_commitment(&CONFIG.secret_key);
                let commit_tx = KeyGenCommitmentTransaction::new(
                    election_tx.id,
                    trustee.id,
                    trustee.public_key,
                    commit,
                );
                let commit_tx = Signed::sign(&CONFIG.secret_key, commit_tx).unwrap();
                crate::store_tx(&commit_tx.into(), db).await;
                return;
            }
        }
    }

    // On commitment transaction, check if we have ALL commitments, and if so, generate a share (if we are a trustee)
    if incoming_tx.transaction_type() == TransactionType::KeyGenCommitment {
        let commit_tx: KeyGenCommitmentTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = {
            let store = MEM_STORE.lock().unwrap();
            store.get_transaction(commit_tx.election).unwrap().into()
        };

        for trustee in &election_tx.trustees {
            if trustee.public_key == CONFIG.public_key {
                // Check that we have enough commitment transactions already
                let commit_txs: Vec<KeyGenCommitmentTransaction> = {
                    let store = MEM_STORE.lock().unwrap();
                    store
                        .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                        .into_iter()
                        .map(|tx| tx.into())
                        .collect()
                };

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
                        &CONFIG.secret_key,
                        &election_tx.trustees,
                        &commitments,
                    );

                    let share_tx = KeyGenShareTransaction::new(
                        election_tx.id,
                        trustee.id,
                        trustee.public_key,
                        shares,
                    );
                    let share_tx = Signed::sign(&CONFIG.secret_key, share_tx).unwrap();
                    crate::store_tx(&share_tx.into(), db).await;
                    return;
                }
            }
        }
    }

    // On keygen transaction, check if we have ALL keygens, and if so, generate a public_key (if we are a trustee)
    if incoming_tx.transaction_type() == TransactionType::KeyGenShare {
        let keygen_tx: KeyGenShareTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = {
            let store = MEM_STORE.lock().unwrap();
            store.get_transaction(keygen_tx.election).unwrap().into()
        };

        for trustee in &election_tx.trustees {
            if trustee.public_key == CONFIG.public_key {
                // Check that we have enough keygen_tx transactions already
                let share_txs: Vec<KeyGenShareTransaction> = {
                    let store = MEM_STORE.lock().unwrap();
                    store
                        .get_multiple(election_tx.id, TransactionType::KeyGenShare)
                        .into_iter()
                        .map(|tx| tx.into())
                        .collect()
                };

                if share_txs.len() == election_tx.trustees.len() {
                    // We have enough shares, generate a public_key transactions
                    let mut trustee = trustee.clone();
                    trustee.num_trustees = election_tx.trustees.len();
                    trustee.threshold = election_tx.trustees_threshold;

                    // Get all commitments
                    let commitments: Vec<(Uuid, KeygenCommitment)> = {
                        let store = MEM_STORE.lock().unwrap();
                        store
                            .get_multiple(election_tx.id, TransactionType::KeyGenCommitment)
                            .into_iter()
                            .map(|tx| tx.into())
                            .map(|tx: KeyGenCommitmentTransaction| (tx.trustee_id, tx.commitment))
                            .collect()
                    };

                    let shares: Vec<(Uuid, EncryptedShare)> = share_txs
                        .into_iter()
                        .map(|tx| (tx.trustee_id, tx.shares.get(&trustee.id).unwrap().clone()))
                        .collect();

                    let (public_key, public_key_proof) = trustee.generate_public_key(
                        &CONFIG.secret_key,
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
                    let pk_tx = Signed::sign(&CONFIG.secret_key, pk_tx).unwrap();
                    crate::store_tx(&pk_tx.into(), db).await;
                    return;
                }
            }
        }
    }

    // On public_key transaction, check if we have ALL public-keys, and if so, generate a encryption_key transaction (if we are the election authority)
    if incoming_tx.transaction_type() == TransactionType::KeyGenPublicKey
        && CONFIG.public_key == CONFIG.authority_public_key
    {
        let pk_tx: KeyGenPublicKeyTransaction = incoming_tx.clone().into(); // TODO: asRef

        // Get the election_tx
        let election_tx: ElectionTransaction = {
            let store = MEM_STORE.lock().unwrap();
            store.get_transaction(pk_tx.election).unwrap().into()
        };

        // Get all public key transactions
        let pk_txs: Vec<KeyGenPublicKeyTransaction> = {
            let store = MEM_STORE.lock().unwrap();
            store
                .get_multiple(election_tx.id, TransactionType::KeyGenPublicKey)
                .into_iter()
                .map(|tx| tx.into())
                .collect()
        };

        if election_tx.trustees.len() == pk_txs.len() {
            // Generate an encryption_key transaction
            let encryption_key_tx = EncryptionKeyTransaction::new(
                election_tx.id,
                CONFIG.authority_public_key.clone(),
                pk_tx.public_key,
            );
            let encryption_key_tx = Signed::sign(&CONFIG.secret_key, encryption_key_tx).unwrap();
            crate::store_tx(&encryption_key_tx.into(), db).await;
            return;
        }
    }

    // TODO: On an VotingEnd transaction start decrypting votes
    // TODO: On a PartialDecrytion transaction see if we can do a full decryption
}
