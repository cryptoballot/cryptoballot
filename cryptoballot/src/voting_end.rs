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

impl CryptoBallotTransaction for VotingEndTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.authority_public_key)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::VotingEnd
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
