use crate::*;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct DecryptionTransaction {
    pub id: Uuid,
    pub election: Uuid,
    pub vote: Uuid,
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    pub fn new(vote: &VoteTransaction, decrypted_vote: Vec<u8>) -> DecryptionTransaction {
        DecryptionTransaction {
            id: Uuid::new_v4(),
            election: vote.election,
            vote: vote.id,
            decrypted_vote,
        }
    }

    // TOOD: add validation:
    //  - Takes vote transaction
    //  - Takes all secret-share stransactions
    //  - validates that the decrypted vote is the same
    pub fn validate(&self) -> Result<(), ()> {
        Ok(())
    }
}

pub fn decrypt_vote(election_key: &[u8], vote: &[u8]) -> Result<Vec<u8>, secp256k1::Error> {
    ecies::decrypt(election_key, vote)
}
