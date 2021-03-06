use crate::*;
use cryptid::threshold::KeygenCommitment;
use ed25519_dalek::PublicKey;
use indexmap::IndexMap;
use x25519_dalek as x25519;

/// Transaction 2: KeyGenCommitment
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenCommitmentTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_index: u8,
    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,

    #[serde(with = "X25519PublicKeyHex")]
    pub x25519_public_key: x25519::PublicKey,
    pub commitment: KeygenCommitment,
}

/// Transaction 3: KeyGenShare
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenShareTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_index: u8,
    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,

    #[serde(with = "indexmap::serde_seq")]
    pub shares: IndexMap<u8, EncryptedShare>,
}

/// Transaction 4: KeyGenPublicKey
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenPublicKeyTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_index: u8,
    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,
    pub public_key: cryptid::elgamal::PublicKey,
    pub public_key_proof: cryptid::threshold::PubkeyProof,
}

/// Transaction 5: EncryptionKey
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionKeyTransaction {
    pub id: Identifier,
    pub election: Identifier,
    #[serde(with = "EdPublicKeyHex")]
    pub authority_public_key: PublicKey,
    pub encryption_key: cryptid::elgamal::PublicKey,
}

impl KeyGenCommitmentTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        trustee_index: u8,
        trustee_public_key: PublicKey,
        x25519_public_key: x25519::PublicKey,
        commitment: KeygenCommitment,
    ) -> Self {
        KeyGenCommitmentTransaction {
            id: Self::build_id(election_id, trustee_index),
            election: election_id,
            trustee_index,
            trustee_public_key,
            x25519_public_key,
            commitment,
        }
    }

    pub fn build_id(election_id: Identifier, trustee_index: u8) -> Identifier {
        let mut unique_info = [0; 16];
        unique_info[0] = trustee_index;
        Identifier::new(
            election_id,
            TransactionType::KeyGenCommitment,
            Some(unique_info),
        )
    }
}

impl CryptoBallotTransaction for KeyGenCommitmentTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::KeyGenCommitment
    }

    /// Validate the transaction
    ///
    /// The validation does the following:
    ///  - Validates that this transaction has been signed by a valid trustee
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election)?;

        let mut trustee_exists = false;
        for trustee in &election.trustees {
            if trustee.index == self.trustee_index && trustee.public_key == self.trustee_public_key
            {
                trustee_exists = true;
            }
        }

        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(self.trustee_index));
        }

        // TODO: Validate the commitment?

        Ok(())
    }
}

impl KeyGenShareTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        trustee_index: u8,
        trustee_public_key: PublicKey,
        shares: IndexMap<u8, EncryptedShare>,
    ) -> Self {
        KeyGenShareTransaction {
            id: Self::build_id(election_id, trustee_index),
            election: election_id,
            trustee_index,
            trustee_public_key,
            shares,
        }
    }

    pub fn build_id(election_id: Identifier, trustee_index: u8) -> Identifier {
        let mut unique_info = [0; 16];
        unique_info[0] = trustee_index;
        Identifier::new(election_id, TransactionType::KeyGenShare, Some(unique_info))
    }
}

impl CryptoBallotTransaction for KeyGenShareTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::KeyGenShare
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
            if trustee.index == self.trustee_index && trustee.public_key == self.trustee_public_key
            {
                trustee_exists = true;
            }
        }
        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(self.trustee_index));
        }

        // Validate that the number of shares match
        if self.shares.len() != election.trustees.len() {
            return Err(ValidationError::WrongNumberOfShares);
        }

        // Validate that all trustees have been given a share
        for trustee in &election.trustees {
            if !self.shares.contains_key(&trustee.index) {
                return Err(ValidationError::TrusteeShareMissing(self.trustee_index));
            }
        }

        Ok(())
    }
}

impl KeyGenPublicKeyTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        trustee_index: u8,
        trustee_public_key: PublicKey,
        public_key: cryptid::elgamal::PublicKey,
        public_key_proof: cryptid::threshold::PubkeyProof,
    ) -> Self {
        KeyGenPublicKeyTransaction {
            id: Self::build_id(election_id, trustee_index),
            election: election_id,
            trustee_index,
            trustee_public_key,
            public_key,
            public_key_proof,
        }
    }

    pub fn build_id(election_id: Identifier, trustee_index: u8) -> Identifier {
        let mut unique_info = [0; 16];
        unique_info[0] = trustee_index;
        Identifier::new(
            election_id,
            TransactionType::KeyGenPublicKey,
            Some(unique_info),
        )
    }
}

impl CryptoBallotTransaction for KeyGenPublicKeyTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::KeyGenPublicKey
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
            if trustee.index == self.trustee_index && trustee.public_key == self.trustee_public_key
            {
                trustee_exists = true;
            }
        }
        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(self.trustee_index));
        }

        Ok(())
    }
}

impl EncryptionKeyTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        authority_public_key: PublicKey,
        encryption_key: cryptid::elgamal::PublicKey,
    ) -> Self {
        EncryptionKeyTransaction {
            id: Self::build_id(election_id),
            election: election_id,
            authority_public_key,
            encryption_key,
        }
    }

    pub fn build_id(election_id: Identifier) -> Identifier {
        Identifier::new(election_id, TransactionType::EncryptionKey, None)
    }
}

impl CryptoBallotTransaction for EncryptionKeyTransaction {
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
        TransactionType::EncryptionKey
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
        let pk_txs: Vec<Signed<KeyGenPublicKeyTransaction>> =
            pk_txs.into_iter().map(|tx| tx.into()).collect();

        // Validate that the number of public key transactions match
        if pk_txs.len() != election.trustees.len() {
            return Err(ValidationError::WrongNumberOfPublicKeyTransactions);
        }

        // Validate that all trustees have a transaction
        for trustee in &election.trustees {
            let mut has_tx = false;
            for tx in &pk_txs {
                if tx.inner().trustee_index == trustee.index
                    && tx.inner().trustee_public_key == trustee.public_key
                {
                    has_tx = true;
                    break;
                }
            }
            if !has_tx {
                return Err(ValidationError::MissingKeyGenPublicKeyTransaction(
                    trustee.index,
                ));
            }
        }

        // Validate that all the encryption keys match
        for tx in &pk_txs {
            if tx.inner().public_key != self.encryption_key {
                return Err(ValidationError::MismatchedEncryptionKey(
                    tx.inner().trustee_index,
                ));
            }
        }

        Ok(())
    }
}
