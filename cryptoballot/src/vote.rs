use crate::*;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use uuid::Uuid;

/// Transaction 2: Vote
///
/// A vote transaction is posted by the voter, and contains their encrypted vote for the contests defined by a ballot.
///
/// The vote contains no idenifying information about the voter, allowing them to vote anonymously.
///
/// Before a voter can post a VoteTransaction, they must first be authenticated by a quorum of authenticator,
/// who certify that they can vote this election and ballot.
#[derive(Serialize, Deserialize, Clone)]
pub struct VoteTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub ballot_id: Uuid,

    /// Vote encrypted by ECIES with the key defined by `ElectionTransaction.encryption_public`
    #[serde(with = "hex_serde")]
    pub encrypted_vote: Vec<u8>,

    /// The public key used to anonymized the voter.
    /// The voter should not reveal that they own this key - doing so will leak their real identity.
    #[serde(with = "EdPublicKeyHex")]
    pub anonymous_key: PublicKey,

    /// A set of authentications, certifying that the anonymous_key provided can vote this election and ballot.
    pub authentication: Vec<Authentication>,
}

impl VoteTransaction {
    /// Create a new vote transaction.
    pub fn new(election_id: Identifier, ballot_id: Uuid) -> (Self, SecretKey) {
        let (secret_key, public_key) = generate_keypair();
        let vote = VoteTransaction {
            id: Identifier::new(election_id, TransactionType::Vote),
            election: election_id,
            ballot_id: ballot_id,
            encrypted_vote: vec![],
            anonymous_key: public_key,
            authentication: vec![],
        };

        (vote, secret_key)
    }

    /// Validate the vote transaction
    pub fn validate(&self, election: &ElectionTransaction) -> Result<(), ValidationError> {
        // TODO: check self.id.election_id vs self.election_id
        if self.election != election.id {
            return Err(ValidationError::ElectionMismatch);
        }
        if election.get_ballot(self.ballot_id).is_none() {
            return Err(ValidationError::BallotDoesNotExist);
        }

        // TODO: minimum authentication needed to be defined in election
        for authn in self.authentication.iter() {
            let authenticator = election
                .get_authenticator(authn.authenticator)
                .ok_or(ValidationError::AuthDoesNotExist)?;

            authenticator
                .verify(
                    election.id,
                    self.ballot_id,
                    &self.anonymous_key,
                    &authn.signature,
                )
                .map_err(|_| ValidationError::AuthFailed)?;
        }

        Ok(())
    }
}

impl Signable for VoteTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        Some(self.anonymous_key)
    }

    fn input(&self) -> Vec<Identifier> {
        // Only requires election as input
        vec![self.election]
    }
}

/// Encrypt a vote with the public key provided by the election transaction (ElectionTransaction.encryption_key)
pub fn encrypt_vote(election_key: &[u8], vote: &[u8]) -> Result<Vec<u8>, secp256k1::Error> {
    let encrypted = ecies::encrypt(election_key, vote)?;
    Ok(encrypted)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_vote() {
        // See tests.rs
    }
}
