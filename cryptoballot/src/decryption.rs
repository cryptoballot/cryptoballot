use crate::*;
use ed25519_dalek::PublicKey;

#[derive(Serialize, Deserialize, Clone)]
pub struct DecryptionTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub vote: Identifier,
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
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

    // TOOD: add validation:
    //  - Takes vote transaction
    //  - Takes all secret-share stransactions
    //  - validates that the decrypted vote is the same
    pub fn validate(&self) -> Result<(), ()> {
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

pub fn decrypt_vote(election_key: &[u8], vote: &[u8]) -> Result<Vec<u8>, secp256k1::Error> {
    ecies::decrypt(election_key, vote)
}
