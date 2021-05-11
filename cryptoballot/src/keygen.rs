use crate::*;
use uuid::Uuid;
use ed25519_dalek::PublicKey;
use cryptid::threshold::KeygenCommitment;
use std::collections::HashMap;

/// Transaction 2: KeyGenCommitmentTransaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenCommitmentTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_id: Uuid,
    pub trustee_public_key: PublicKey,
    pub commitment: KeygenCommitment,
}

/// Transaction 3: KeyGenShareTransaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenShareTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_id: Uuid,
    pub trustee_public_key: PublicKey,
    pub shares: HashMap<Uuid, Vec<u8>>,
}

/// Transaction 4: KeyGenPublicKeyTransaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenPublicKeyTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_id: Uuid,
    pub trustee_public_key: PublicKey,
    pub public_key: cryptid::elgamal::PublicKey,
}


impl Signable for KeyGenCommitmentTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // Only requires election as input
        vec![self.election]
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid trustee
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;
        
        let mut trustee_exists = false;
        for trustee in &election.trustees {
            if trustee.id == self.trustee_id && trustee.public_key == self.trustee_public_key {
                trustee_exists = true;
            }
        }

        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(
                self.trustee_id
            ));
        }

        // TODO: Validate the commitment somehow?

        Ok(())
    }
}


impl Signable for KeyGenShareTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // Only requires election as input
        vec![self.election, ]
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid trustee
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;
        
        let mut trustee_exists = false;
        for trustee in &election.trustees {
            if trustee.id == self.trustee_id && trustee.public_key == self.trustee_public_key {
                trustee_exists = true;
            }
        }

        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(
                self.trustee_id
            ));
        }

        // TODO: Validate the commitment somehow?

        Ok(())
    }
}