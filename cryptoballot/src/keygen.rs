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
    pub shares: HashMap<Uuid, EncryptedShare>,
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

/// Transaction 4: PublicKeyConfirmationTransaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionKeyTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub authority_public_key: PublicKey,
    pub encryption_key: cryptid::elgamal::PublicKey,
}

impl KeyGenCommitmentTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        trustee_id: Uuid,
        trustee_public_key: PublicKey,
        commitment: KeygenCommitment,
    ) -> Self {
        KeyGenCommitmentTransaction {
            id: Identifier::new(election, TransactionType::KeyGenCommitment, trustee_id.as_bytes()),
            election: election,
            trustee_id,
            trustee_public_key,
            commitment
        }
    }
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


impl KeyGenShareTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        trustee_id: Uuid,
        trustee_public_key: PublicKey,
        shares: HashMap<Uuid, EncryptedShare>,
    ) -> Self {
        KeyGenShareTransaction {
            id: Identifier::new(election, TransactionType::KeyGenShare, trustee_id.as_bytes()),
            election: election,
            trustee_id,
            trustee_public_key,
            shares
        }
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
        // TODO: This needs to change (or be removed)
        vec![self.election]
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid trustee
    ///  - Validates that there is one share per trustee in the election
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        // Validate that this trustee exists
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

        // Validate that the number of shares match
        if self.shares.len() != election.trustees.len() {
            return Err(ValidationError::WrongNumberOfShares); 
        }

        // Validate that all trustees have been given a share
        for trustee in &election.trustees {
            if !self.shares.contains_key(&trustee.id) {
                return Err(ValidationError::TrusteeShareMissing(
                    self.trustee_id
                )); 
            }
        }

        Ok(())
    }
}

impl KeyGenPublicKeyTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        trustee_id: Uuid,
        trustee_public_key: PublicKey,
        public_key: cryptid::elgamal::PublicKey,
    ) -> Self {
        KeyGenPublicKeyTransaction {
            id: Identifier::new(election, TransactionType::KeyGenPublicKey, trustee_id.as_bytes()),
            election: election,
            trustee_id,
            trustee_public_key,
            public_key
        }
    }
}

impl Signable for KeyGenPublicKeyTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // Only requires election as input
        // TODO: This needs to change (or be removed)
        vec![self.election]
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid trustee
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        // Validate that this trustee exists
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

        Ok(())
    }
}

impl EncryptionKeyTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election: Identifier,
        authority_public_key: PublicKey,
        encryption_key: cryptid::elgamal::PublicKey,
    ) -> Self {
        EncryptionKeyTransaction {
            id: Identifier::new(election, TransactionType::EncryptionKey, &[0; 16]),
            election: election,
            authority_public_key,
            encryption_key,
        }
    }
}

impl Signable for EncryptionKeyTransaction {
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
    ///  - Validates that this transaction has been signed by a valid trustee
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        // Validate the the election authority public key is the same
        if self.authority_public_key != election.authority_public {
            return Err(ValidationError::AuthorityPublicKeyMismatch); 
        }

        // Get all keygen_public_key transactions
        let pk_txs = store.get_multiple(self.election, TransactionType::KeyGenPublicKey);
        let pk_txs: Vec<Signed<KeyGenPublicKeyTransaction>> = pk_txs.into_iter().map(|tx| tx.into()).collect();

        // Validate that the number of public key transactions match
        if pk_txs.len() != election.trustees.len() {
            return Err(ValidationError::WrongNumberOfPublicKeyTransactions); 
        }

        // Validate that all trustees have a transaction
        for trustee in &election.trustees {
            let mut has_tx = false;
            for tx in &pk_txs {
                if tx.inner().trustee_id == trustee.id && tx.inner().trustee_public_key == trustee.public_key {
                    has_tx = true;
                    break;
                }
            }
            if !has_tx {
                return Err(ValidationError::MissingKeyGenPublicKeyTransaction(trustee.id)); 
            }
        }

        // Validate that all the encryption keys match
        for tx in &pk_txs {
            if tx.inner().public_key != self.encryption_key {
                return Err(ValidationError::MismatchedEncryptionKey(tx.inner().trustee_id)); 
            }
        }

        Ok(())
    }
}