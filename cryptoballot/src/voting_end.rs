use crate::*;
use ed25519_dalek::PublicKey;

/// Transaction 7: VotingEnd
#[derive(Serialize, Deserialize, Clone)]
pub struct VotingEndTransaction {
    pub id: Identifier,
    pub election: Identifier,
    #[serde(with = "EdPublicKeyHex")]
    pub authority_public_key: PublicKey,
}

impl VotingEndTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(election: Identifier, authority_public_key: PublicKey) -> Self {
        VotingEndTransaction {
            id: Identifier::new(election, TransactionType::VotingEnd, None),
            election: election,
            authority_public_key,
        }
    }
}

impl Signable for VotingEndTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.authority_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // Only requires election as input
        // TODO: This may beed to change
        vec![self.election]
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid election authority
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        // Validate the the election authority public key is the same
        if self.authority_public_key != election.authority_public {
            return Err(ValidationError::AuthorityPublicKeyMismatch);
        }

        Ok(())
    }
}
