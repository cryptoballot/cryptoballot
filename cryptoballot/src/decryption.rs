use crate::*;
use cryptid::elgamal::Ciphertext;
use cryptid::threshold::DecryptShare;
use cryptid::threshold::Threshold;
use ed25519_dalek::PublicKey;
use std::collections::HashMap;

/// Transaction 8: Partial Decryption
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialDecryptionTransaction {
    pub id: Identifier,
    pub election_id: Identifier,

    /// The upstream transaction ID, either the vote transaction ID or the mix transaction ID
    pub upstream_id: Identifier,

    /// If this is from a mix, the index of the ciphertext in the `mixed_ciphertexts` field, or `0` if from a vote transaction
    pub upstream_index: u16,

    pub trustee_index: u8,

    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,

    pub partial_decryption: DecryptShare,
}

impl PartialDecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        upstream_id: Identifier,
        upstream_index: u16,
        trustee_index: u8,
        trustee_public_key: PublicKey,
        partial_decryption: DecryptShare,
    ) -> Self {
        PartialDecryptionTransaction {
            id: PartialDecryptionTransaction::build_id(
                election_id,
                upstream_id,
                upstream_index,
                trustee_index,
            ),
            election_id,
            upstream_id,
            upstream_index,
            trustee_index,
            trustee_public_key,
            partial_decryption,
        }
    }

    // Has an ID format of <election-id><type><upstream-tx-type><voter-anonymous-key/mix-unique-info><trustee-index>
    pub fn build_id(
        election_id: Identifier,
        upstream_id: Identifier,
        upstream_index: u16,
        trustee_index: u8,
    ) -> Identifier {
        let upstream_index = upstream_index.to_be_bytes();
        let mut unique_info = [0; 16];

        unique_info[0] = upstream_id.transaction_type.into(); // 1 byte

        if upstream_id.transaction_type == TransactionType::Mix {
            unique_info[1..=12].copy_from_slice(&upstream_id.unique_info[..12]); // 12 bytes
            unique_info[13..=14].copy_from_slice(&upstream_index); // 2 bytes
        }
        if upstream_id.transaction_type == TransactionType::Vote {
            // 14 bytes
            unique_info[1..=14].copy_from_slice(&upstream_id.unique_info[..14]);
        }

        unique_info[15] = trustee_index; // 1 byte

        Identifier::new(
            election_id,
            TransactionType::PartialDecryption,
            Some(unique_info),
        )
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
        vec![self.election_id, self.upstream_id]
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election_id)?;

        // Make sure the trustee is correct
        let mut trustee = None;
        for election_trustee in election.get_full_trustees() {
            if election_trustee.index == self.trustee_index
                && election_trustee.public_key == self.trustee_public_key
            {
                trustee = Some(election_trustee);
                break;
            }
        }
        let trustee = trustee.ok_or(ValidationError::TrusteeDoesNotExist(self.trustee_index))?;

        // Check the ID
        if Self::build_id(
            self.election_id,
            self.upstream_id,
            self.upstream_index,
            trustee.index,
        ) != self.id
        {
            return Err(ValidationError::IdentifierBadComposition);
        }
        // Make sure the mix index is equal to the minimum number of mixes

        // Make sure voting end exists
        let voting_end_id = Identifier::new(self.election_id, TransactionType::VotingEnd, None);
        if store.get_transaction(voting_end_id).is_none() {
            return Err(ValidationError::MisingVotingEndTransaction);
        }

        // Get the ciphertext either from the vote or the mix
        // Get the ciphertext either from the vote or the mix
        let encrypted_vote: Ciphertext = encrypted_vote_from_upstream_tx(
            store,
            self.upstream_id,
            self.upstream_index,
            &election.mix_config,
        )?;

        // Get the public key transaction for this trustee
        let pkey_tx_id = KeyGenPublicKeyTransaction::build_id(self.election_id, self.trustee_index);
        let public_key = store.get_keygen_public_key(pkey_tx_id)?;

        // Validate that the public_key transaction matches
        if self.trustee_index != public_key.inner().trustee_index
            || self.trustee_public_key != public_key.inner().trustee_public_key
        {
            return Err(ValidationError::TrusteePublicKeyMismatch(
                self.trustee_index,
            ));
        }

        // Verify the partial decryption proof
        if !self
            .partial_decryption
            .verify(&public_key.inner().public_key_proof, &encrypted_vote)
        {
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

    /// The Vote or the Mix transaction, depending on if we are using a mixnet
    pub upstream_id: Identifier,

    /// If we are using a mixnet, the index in the reencrypted field, or `0` if upstream is a vote transaction
    pub upstream_index: u16,

    /// The trustees (as defined by index) who's PartialDecryption transactions were used to produce this full decryption
    pub trustees: Vec<u8>,

    /// The decrypted vote
    #[serde(with = "hex_serde")]
    pub decrypted_vote: Vec<u8>,
}

impl DecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        upstream_id: Identifier,
        upstream_index: u16,
        trustees: Vec<u8>,
        decrypted_vote: Vec<u8>,
    ) -> DecryptionTransaction {
        debug_assert!(election_id.election_id == upstream_id.election_id);

        DecryptionTransaction {
            id: Self::build_id(election_id, upstream_id, upstream_index),
            election_id,
            upstream_id,
            upstream_index,
            trustees,
            decrypted_vote,
        }
    }

    pub fn build_id(
        election_id: Identifier,
        upstream_id: Identifier,
        upstream_index: u16,
    ) -> Identifier {
        // TODO: Review code to make sure this is correct against both the mix ID and the vote ID
        let upstream_index = upstream_index.to_be_bytes();
        let mut unique_info = upstream_id.unique_info;
        unique_info[14..16].copy_from_slice(&upstream_index);
        Identifier::new(election_id, TransactionType::Decryption, Some(unique_info))
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
        inputs.push(self.upstream_id);

        // TODO: Somehow the partial-decrypt transactions?

        inputs
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        // Check the ID
        if Self::build_id(self.election_id, self.upstream_id, self.upstream_index) != self.id {
            return Err(ValidationError::IdentifierBadComposition);
        }

        let election = store.get_election(self.election_id)?;

        // Get the ciphertext either from the vote or the mix
        let encrypted_vote: Ciphertext = encrypted_vote_from_upstream_tx(
            store,
            self.upstream_id,
            self.upstream_index,
            &election.mix_config,
        )?;

        // Get all pubkeys mapped by trustee ID
        let pubkeys: Vec<KeyGenPublicKeyTransaction> = store
            .get_multiple(self.election_id, TransactionType::KeyGenPublicKey)
            .into_iter()
            .map(|tx| tx.into())
            .map(|tx: Signed<KeyGenPublicKeyTransaction>| tx.tx)
            .collect();

        // Get all partial decryptions mapped by trustee ID
        let mut partials = Vec::with_capacity(self.trustees.len());
        for trustee_index in self.trustees.iter() {
            let trustee = election
                .inner()
                .get_trustee(*trustee_index)
                .ok_or(ValidationError::TrusteeDoesNotExist(*trustee_index))?;
            let partial_id = PartialDecryptionTransaction::build_id(
                self.election_id,
                self.upstream_id,
                self.upstream_index,
                trustee.index,
            );
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
            &encrypted_vote,
            election.inner().trustees_threshold,
            &election.inner().trustees,
            &pubkeys,
            &partials,
        )?;

        if decrypted != self.decrypted_vote {
            return Err(ValidationError::VoteDecryptionMismatch);
        }

        Ok(())
    }
}

/// Decrypt the vote from the given partial decryptions.
pub fn decrypt_vote(
    encrypted_vote: &Ciphertext,
    trustees_threshold: usize,
    trustees: &[Trustee],
    pubkeys: &[KeyGenPublicKeyTransaction],
    partials: &[PartialDecryptionTransaction],
) -> Result<Vec<u8>, ValidationError> {
    // Map pubkeys by trustee index
    let pubkeys: HashMap<u8, &KeyGenPublicKeyTransaction> = pubkeys
        .into_iter()
        .map(|tx| (tx.trustee_index, tx))
        .collect();

    // Map partials by trustee index
    let partials: HashMap<u8, &PartialDecryptionTransaction> = partials
        .into_iter()
        .map(|tx| (tx.trustee_index, tx))
        .collect();

    // Decrypt the vote
    let mut decrypt = cryptid::threshold::Decryption::new(trustees_threshold, encrypted_vote);

    for trustee in trustees {
        if let Some(partial) = partials.get(&trustee.index) {
            if let Some(pubkey) = pubkeys.get(&trustee.index) {
                decrypt.add_share(
                    trustee.index as usize,
                    &pubkey.public_key_proof,
                    &partial.partial_decryption,
                );
            }
        };
    }

    decrypt
        .finish()
        .map_err(|e| ValidationError::VoteDecryptionFailed(e))
}

/// A convenience function for getting an encrypted-vote from some upstream transaction ID.
/// The upstream transaction should either be a mixnet or a vote transaction.
pub fn encrypted_vote_from_upstream_tx<S: Store>(
    store: &S,
    upstream_id: Identifier,
    upstream_index: u16,
    mix_config: &Option<MixConfig>,
) -> Result<Ciphertext, ValidationError> {
    // Get the ciphertext either from the vote or the mix
    let ciphertext: Ciphertext = match upstream_id.transaction_type {
        TransactionType::Vote => {
            if mix_config.is_some() {
                return Err(ValidationError::InvalidUpstreamID);
            }
            if upstream_index != 0 {
                return Err(ValidationError::InvalidUpstreamIndex);
            }

            store.get_vote(upstream_id)?.tx.encrypted_vote
        }
        TransactionType::Mix => {
            let mix = store.get_mix(upstream_id)?.tx;

            // Check mix config
            if mix_config.is_none() {
                return Err(ValidationError::InvalidUpstreamID);
            }

            if upstream_index >= mix.mixed_ciphertexts.len() as u16 {
                return Err(ValidationError::InvalidUpstreamIndex);
            }

            let mut rencryptions = mix.mixed_ciphertexts;
            rencryptions.swap_remove(upstream_index as usize)
        }
        _ => {
            return Err(ValidationError::InvalidUpstreamID);
        }
    };

    Ok(ciphertext)
}
