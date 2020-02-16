use crate::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct DecryptionTransaction {
    pub id: TransactionIdentifier,
    pub election: TransactionIdentifier,
    pub vote: TransactionIdentifier,
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    pub fn new(
        election: TransactionIdentifier,
        vote: TransactionIdentifier,
        decrypted_vote: Vec<u8>,
    ) -> DecryptionTransaction {
        // TODO: sanity check to make sure election and vote are in same election
        // This could be a debug assert

        DecryptionTransaction {
            id: TransactionIdentifier::new(election, TransactionType::Decryption),
            election: election,
            vote: vote,
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
