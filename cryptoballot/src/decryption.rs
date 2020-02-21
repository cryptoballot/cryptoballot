use crate::*;
use ed25519_dalek::PublicKey;
use sharks::{Share, Sharks};
use uuid::Uuid;

/// Transaction 4: Decryption
///
/// After a quorum of Trustees have posted SharedSecret transactions (#3), any node may produce
/// a DecryptionTransaction. One DecryptionTransaction is produced for each Vote (#2) transaction,
/// decrypting the vote using the secret recovered from the SharedSecret transactions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub vote: Identifier,
    pub trustees: Vec<Uuid>,

    #[serde(with = "hex_serde")]
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        vote: Identifier,
        trustees: Vec<Uuid>,
        decrypted_vote: Vec<u8>,
    ) -> DecryptionTransaction {
        // TODO: sanity check to make sure election and vote are in same election
        // This could be a debug assert
        DecryptionTransaction {
            id: Identifier::new(election, TransactionType::Decryption, &vote.to_bytes()),
            election: election,
            vote: vote,
            trustees: trustees,
            decrypted_vote,
        }
    }
}

impl Signable for DecryptionTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        None
    }

    fn inputs(&self) -> Vec<Identifier> {
        let mut inputs = Vec::<Identifier>::with_capacity(2 + self.trustees.len());
        inputs.push(self.election);
        inputs.push(self.vote);

        for trustee in self.trustees.iter() {
            inputs.push(SecretShareTransaction::build_id(self.election, *trustee))
        }

        inputs
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Takes vote transaction and all secret-share stransactions
    ///  - validates that the decrypted vote is the same
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;
        let vote = store.get_vote(self.vote)?;

        // TODO: implement some sort of "get_multiple" in Store
        let mut shares = Vec::with_capacity(election.trustees.len());
        for trustee in election.trustees.iter() {
            let secret_share_id = SecretShareTransaction::build_id(self.election, trustee.id);
            let secret_share_tx = store.get_secret_share(secret_share_id).ok();
            if let Some(secret_share_tx) = secret_share_tx {
                shares.push(secret_share_tx.secret_share.clone());
            }
        }

        // Make sure we have enough shares
        let required_shares = election.trustees_threshold as usize;
        if shares.len() < required_shares {
            return Err(ValidationError::NotEnoughShares(
                required_shares,
                shares.len(),
            ));
        }

        // TODO: Check the secret_shares.len() >= election.trustees_threshold

        // Recover election key from two trustees
        let election_key = recover_secret_from_shares(election.trustees_threshold, shares)
            .map_err(|_| ValidationError::SecretRecoveryFailed)?;

        let decrypted_vote = decrypt_vote(&election_key, &vote.encrypted_vote)
            .map_err(|_| ValidationError::DecryptVoteFailed)?;

        if decrypted_vote != self.decrypted_vote {
            return Err(ValidationError::MismatchedDecryptedVote);
        }

        Ok(())
    }
}

/// Given a set of secret shares recovered from all SecretShareTransaction, reconstruct
/// the secret decryption key. The decryption key can then be used to decrypt votes and create
/// a DecryptionTransaction.
pub fn recover_secret_from_shares(threshold: u8, shares: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let shares: Vec<Share> = shares.iter().map(|s| Share::from(s.as_slice())).collect();

    let sharks = Sharks(threshold);

    let secret = sharks
        .recover(&shares)
        .map_err(|_| Error::SecretRecoveryFailed)?;

    Ok(secret)
}

/// Decrypt the vote from the given recovered decryption key.
///
/// `encrypted_vote` is taken from `VoteTransaction::encrypted_vote`.
pub fn decrypt_vote(election_key: &[u8], encrypted_vote: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(ecies::decrypt(election_key, encrypted_vote)?)
}
