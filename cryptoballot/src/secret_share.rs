use crate::*;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use uuid::Uuid;

/// Transaction 3: SecretShare
///
/// The SecretShareTransaction is published by trustees, with one transaction created per trustee.
///
/// After the trustee determins that voting is over and all votes may be decrypted, they publish
/// a SecretShareTransaction, revealing the secret-share that was delt to them by the election authority.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretShareTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_id: Uuid,

    #[serde(with = "EdPublicKeyHex")]
    pub public_key: PublicKey,

    #[serde(with = "hex_serde")]
    pub secret_share: Vec<u8>,
}

impl SecretShareTransaction {
    /// Create a new SecretShare Transaction
    pub fn new(election_id: Identifier, trustee: Trustee, secret_share: Vec<u8>) -> Self {
        let secret_share = SecretShareTransaction {
            id: Self::build_id(election_id, trustee.id),
            election: election_id,
            trustee_id: trustee.id,
            public_key: trustee.public_key,
            secret_share: secret_share,
        };

        secret_share
    }

    pub fn build_id(election_id: Identifier, trustee_id: Uuid) -> Identifier {
        Identifier::new(
            election_id,
            TransactionType::SecretShare,
            trustee_id.as_bytes(),
        )
    }
}

impl Signable for SecretShareTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        Some(self.public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // Only requires election as input
        vec![self.election]
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        // TODO: check self.id.election_id vs self.election_id
        if self.election != election.id {
            return Err(ValidationError::ElectionMismatch);
        }
        let trustee = election
            .get_trustee(self.trustee_id)
            .ok_or(ValidationError::TrusteeDoesNotExist(self.trustee_id))?;

        if trustee.public_key != self.public_key {
            return Err(ValidationError::InvalidPublicKey);
        }

        Ok(())
    }
}

