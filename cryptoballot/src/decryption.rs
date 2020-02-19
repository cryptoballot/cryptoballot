use crate::*;
use ed25519_dalek::PublicKey;

/// Transaction 4: Decryption
///
/// After a quorum of Trustees have posted SharedSecret transactions (#3), any node may produce
/// a DecryptionTransaction. One DecryptionTransaction is produced for each Vote (#2) transaction,
/// decrypting the vote using the secret recovered from the SharedSecret transactions.
#[derive(Serialize, Deserialize, Clone)]
pub struct DecryptionTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub vote: Identifier,

    #[serde(with = "hex_serde")]
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        vote: Identifier,
        decrypted_vote: Vec<u8>,
    ) -> DecryptionTransaction {
        // TODO: sanity check to make sure election and vote are in same election
        // This could be a debug assert

        DecryptionTransaction {
            id: Identifier::new(election, TransactionType::Decryption),
            election: election,
            vote: vote,
            decrypted_vote,
        }
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Takes vote transaction and all secret-share stransactions
    ///  - validates that the decrypted vote is the same
    pub fn validate(
        &self,
        election: &ElectionTransaction,
        vote: &VoteTransaction,
        secret_shares: &[SecretShareTransaction],
    ) -> Result<(), ValidationError> {
        let mut shares = Vec::with_capacity(election.trustees_threshold as usize);
        for secret_share_tx in secret_shares.iter() {
            shares.push(secret_share_tx.secret_share.clone());
        }

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

impl Signable for DecryptionTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        None
    }
}

/// Decrypt the vote from the given recovered election key.
///
/// `encrypted_vote` is taken from `VoteTransaction::encrypted_vote`.
pub fn decrypt_vote(election_key: &[u8], encrypted_vote: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(ecies::decrypt(election_key, encrypted_vote)?)
}
