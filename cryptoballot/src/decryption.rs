use crate::*;
use cryptid::elgamal::Ciphertext;
use cryptid::threshold::DecryptShare;
use cryptid::threshold::Threshold;
use ed25519_dalek::PublicKey;
use sharks::{Share, Sharks};
use std::collections::HashMap;
use std::convert::TryFrom;
use uuid::Uuid;

/// Transaction 8: Partial Decryption
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialDecryptionTransaction {
    pub id: Identifier,
    pub election_id: Identifier,
    pub vote_id: Identifier,
    pub trustee_id: Uuid,

    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,
    pub partial_decryption: DecryptShare,
}

impl PartialDecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        vote_id: Identifier,
        trustee_id: Uuid,
        trustee_public_key: PublicKey,
        partial_decryption: DecryptShare,
    ) -> Self {
        PartialDecryptionTransaction {
            id: PartialDecryptionTransaction::build_id(election_id, vote_id, trustee_id),
            election_id,
            vote_id,
            trustee_id,
            trustee_public_key,
            partial_decryption,
        }
    }

    pub fn build_id(election_id: Identifier, vote_id: Identifier, trustee_id: Uuid) -> Identifier {
        let mut unique_info = [0; 48];
        unique_info[0..16].copy_from_slice(trustee_id.as_bytes());
        unique_info[16..].copy_from_slice(&vote_id.to_bytes());

        Identifier::new(election_id, TransactionType::Decryption, &unique_info)
    }
}

impl Signable for PartialDecryptionTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        vec![self.election_id, self.vote_id]
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election_id)?;

        let voting_end_id = Identifier::new(self.election_id, TransactionType::VotingEnd, &[0; 16]);
        if store.get_transaction(voting_end_id).is_none() {
            return Err(ValidationError::MisingVotingEndTransaction);
        }

        let vote = store.get_vote(self.vote_id)?;

        // Get the public key transaction for this trustee
        let pkey_tx_id = Identifier::new(
            self.election_id,
            TransactionType::KeyGenPublicKey,
            self.trustee_id.as_bytes(),
        );
        let public_key = store.get_keygen_public_key(pkey_tx_id)?;

        // Validate that the public_key transaction matches
        if self.trustee_id != public_key.inner().trustee_id
            || self.trustee_public_key != public_key.inner().trustee_public_key
        {
            return Err(ValidationError::TrusteePublicKeyMismatch(self.trustee_id));
        }

        // Validate that this trustee exists
        let mut trustee_exists = false;
        for trustee in &election.trustees {
            if trustee.id == self.trustee_id && trustee.public_key == self.trustee_public_key {
                trustee_exists = true;
            }
        }
        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(self.trustee_id));
        }

        // Verify the partial decryption proof
        if !self.partial_decryption.verify(
            &public_key.inner().public_key_proof,
            &vote.inner().encrypted_vote,
        ) {
            return Err(ValidationError::PartialDecryptionProofFailed);
        }

        Ok(())
    }
}

/// Transaction 9: Decryption
///
/// After a quorum of Trustees have posted a PartialDecryption transactions, any node may produce
/// a DecryptionTransaction. One DecryptionTransaction is produced for each Vote transaction,
/// decrypting the vote and producing a proof of correct decryption.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionTransaction {
    pub id: Identifier,
    pub election_id: Identifier,
    pub vote_id: Identifier,
    pub trustees: Vec<Uuid>,

    #[serde(with = "hex_serde")]
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        vote_id: Identifier,
        trustees: Vec<Uuid>,
        decrypted_vote: Vec<u8>,
    ) -> DecryptionTransaction {
        // TODO: sanity check to make sure election and vote are in same election
        // This could be a debug assert
        DecryptionTransaction {
            id: Identifier::new(
                election_id,
                TransactionType::Decryption,
                &vote_id.to_bytes(),
            ),
            election_id,
            vote_id,
            trustees,
            decrypted_vote,
        }
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

    fn inputs(&self) -> Vec<Identifier> {
        let mut inputs = Vec::<Identifier>::with_capacity(2 + self.trustees.len());
        inputs.push(self.election_id);
        inputs.push(self.vote_id);

        for trustee in self.trustees.iter() {
            inputs.push(Identifier::new(
                self.election_id,
                TransactionType::KeyGenPublicKey,
                trustee.as_bytes(),
            ));

            inputs.push(PartialDecryptionTransaction::build_id(
                self.election_id,
                self.vote_id,
                *trustee,
            ));
        }

        inputs
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election_id)?;

        let voting_end_id = Identifier::new(self.election_id, TransactionType::VotingEnd, &[0; 16]);
        if store.get_transaction(voting_end_id).is_none() {
            return Err(ValidationError::MisingVotingEndTransaction);
        }

        let vote = store.get_vote(self.vote_id)?;

        // Get all pubkeys mapped by trustee ID
        let pubkeys: Vec<KeyGenPublicKeyTransaction> = store
            .get_multiple(self.election_id, TransactionType::KeyGenPublicKey)
            .into_iter()
            .map(|tx| tx.into())
            .map(|tx: Signed<KeyGenPublicKeyTransaction>| tx.tx)
            .collect();

        // Get all partial decryptions mapped by trustee ID
        let mut partials = Vec::with_capacity(self.trustees.len());
        for trustee_id in self.trustees.iter() {
            let partial_id =
                PartialDecryptionTransaction::build_id(self.election_id, self.vote_id, *trustee_id);
            let partial = store.get_partial_decryption(partial_id)?;

            partials.push(partial.tx);
        }

        // Make sure we have enough shares
        let required_shares = election.trustees_threshold as usize;
        if partials.len() < required_shares {
            return Err(ValidationError::NotEnoughShares(
                required_shares,
                partials.len(),
            ));
        }

        // Decrypt the vote
        let decrypted = decrypt_vote(
            &vote.encrypted_vote,
            election.inner().trustees_threshold,
            &election.inner().trustees,
            &pubkeys,
            &partials,
        )
        .map_err(|e| ValidationError::VoteDecryptionFailed(e))?;

        if decrypted != self.decrypted_vote {
            return Err(ValidationError::VoteDecryptionMismatch);
        }

        Ok(())
    }
}

/// Given a set of secret shares recovered from all SecretShareTransaction, reconstruct
/// the secret decryption key. The decryption key can then be used to decrypt votes and create
/// a DecryptionTransaction.
pub fn recover_secret_from_shares(threshold: u8, shares: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    // TODO: Remove this unwrap
    let shares: Vec<Share> = shares
        .iter()
        .map(|s| Share::try_from(s.as_slice()).unwrap())
        .collect();

    let sharks = Sharks(threshold);

    let secret = sharks
        .recover(&shares)
        .map_err(|_| Error::SecretRecoveryFailed)?;

    Ok(secret)
}

/// Decrypt the vote from the given partial decryptions.
pub fn decrypt_vote(
    encrypted_vote: &Ciphertext,
    trustees_threshold: usize,
    trustees: &[Trustee],
    pubkeys: &[KeyGenPublicKeyTransaction],
    partials: &[PartialDecryptionTransaction],
) -> Result<Vec<u8>, cryptid::CryptoError> {
    // Map pubkeys by trustee ID
    let pubkeys: HashMap<Uuid, &KeyGenPublicKeyTransaction> =
        pubkeys.into_iter().map(|tx| (tx.trustee_id, tx)).collect();

    // Map partials by trustee ID
    let partials: HashMap<Uuid, &PartialDecryptionTransaction> =
        partials.into_iter().map(|tx| (tx.trustee_id, tx)).collect();

    // Decrypt the vote
    let mut decrypt = cryptid::threshold::Decryption::new(trustees_threshold, encrypted_vote);

    for trustee in trustees {
        if let Some(partial) = partials.get(&trustee.id) {
            if let Some(pubkey) = pubkeys.get(&trustee.id) {
                decrypt.add_share(
                    trustee.index,
                    &pubkey.public_key_proof,
                    &partial.partial_decryption,
                );
            }
        };
    }

    decrypt.finish()
}
