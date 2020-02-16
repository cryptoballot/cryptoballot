use crate::*;
use ed25519_dalek::PublicKey;
use uuid::Uuid;

pub struct VoteTransaction {
    pub id: Uuid,
    pub election: Uuid,
    pub encrypted_vote: Vec<u8>,
    pub ballot_id: Uuid,
    pub public_key: PublicKey,
    pub authentication: Vec<Authentication>,
}

impl VoteTransaction {
    pub fn validate(&self, election: &ElectionTransaction) -> Result<(), ()> {
        if self.election != election.id {
            // TODO: return error
        }
        if election.get_ballot(self.ballot_id).is_none() {
            // TODO: return error
        }

        // TODO: minimum authentication needed
        for authn in self.authentication.iter() {
            // TODO: ok_or
            let authenticator = election.get_authenticatort(authn.authenticator).unwrap();

            authenticator
                .verify(
                    election.id,
                    self.ballot_id,
                    &self.public_key,
                    &authn.signature,
                )
                .unwrap();
        }

        Ok(())
    }
}

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
