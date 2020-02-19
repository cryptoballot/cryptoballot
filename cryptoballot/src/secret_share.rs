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
#[derive(Serialize, Deserialize, Clone)]
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
            id: Identifier::new(election_id, TransactionType::SecretShare),
            election: election_id,
            trustee_id: trustee.id,
            public_key: trustee.public_key,
            secret_share: secret_share,
        };

        secret_share
    }

    /// Validate the transaction
    pub fn validate(&self, election: &ElectionTransaction) -> Result<(), ValidationError> {
        // TODO: check self.id.election_id vs self.election_id
        if self.election != election.id {
            return Err(ValidationError::ElectionMismatch);
        }
        let trustee = election
            .get_trustee(self.trustee_id)
            .ok_or(ValidationError::TrusteeDoesNotExist)?;

        if trustee.public_key != self.public_key {
            return Err(ValidationError::InvalidPublicKey);
        }

        Ok(())
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
}

/// A trustee is responsible for safeguarding a secret share (a portion of the secret vote decryption key),
/// distributed by the election authority via Shamir Secret Sharing.
///
/// Most elections will have a handful of trustees (between 3 and 30), with a quorum being set to about 2/3
/// the total number of trustees. Any quorum of trustees may decrypt the votes.
#[derive(Serialize, Deserialize, Clone)]
pub struct Trustee {
    pub id: uuid::Uuid,

    #[serde(with = "EdPublicKeyHex")]
    pub public_key: PublicKey,
}

impl Trustee {
    /// Create a new trustee
    pub fn new() -> (Self, SecretKey) {
        let (secret, public) = generate_keypair();

        let trustee = Trustee {
            id: Uuid::new_v4(),
            public_key: public,
        };
        return (trustee, secret);
    }
}
