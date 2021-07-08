use crate::*;
use cryptid::elgamal::Ciphertext;
use cryptid::threshold::DecryptShare;
use cryptid::threshold::Threshold;
use ed25519_dalek::PublicKey;
use prost::Message;
use std::collections::HashMap;

/// Transaction 9: Partial Decryption
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialDecryptionTransaction {
    pub id: Identifier,
    pub election_id: Identifier,

    /// The upstream transaction ID, either the vote transaction ID or the mix transaction ID
    pub upstream_id: Identifier,

    /// If this is from a mix, the index of the ciphertext in the `mixed_ciphertexts` field, or `0` if from a vote transaction
    pub upstream_index: u16,

    /// The contest index this decryption is for
    pub contest_index: u32,

    pub trustee_index: u8,

    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,

    pub partial_decryption: Vec<DecryptShare>,
}

impl PartialDecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        upstream_id: Identifier,
        upstream_index: u16,
        trustee_index: u8,
        contest_index: u32,
        trustee_public_key: PublicKey,
        partial_decryption: Vec<DecryptShare>,
    ) -> Self {
        PartialDecryptionTransaction {
            id: PartialDecryptionTransaction::build_id(
                election_id,
                upstream_id,
                contest_index,
                upstream_index,
                trustee_index,
            ),
            election_id,
            upstream_id,
            upstream_index,
            trustee_index,
            contest_index,
            trustee_public_key,
            partial_decryption,
        }
    }

    // Has an ID format of <election-id><type><upstream-tx-type><voter-anonymous-key/mix-unique-info><trustee-index>
    pub fn build_id(
        election_id: Identifier,
        upstream_id: Identifier,
        contest_index: u32,
        upstream_index: u16,
        trustee_index: u8,
    ) -> Identifier {
        let unique_info =
            build_unique_info(upstream_id, contest_index, upstream_index, trustee_index);

        Identifier::new(
            election_id,
            TransactionType::PartialDecryption,
            Some(unique_info),
        )
    }
}

impl CryptoBallotTransaction for PartialDecryptionTransaction {
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
        self.election_id
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::Decryption
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
            self.contest_index,
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
        let encrypted_vote: Vec<Ciphertext> = encrypted_vote_from_upstream_tx(
            store,
            self.upstream_id,
            self.upstream_index,
            self.contest_index,
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

        if encrypted_vote.len() != self.partial_decryption.len() {
            // TODO: Use a dedicated errror
            return Err(ValidationError::PartialDecryptionProofFailed);
        }

        // Verify the partial decryption proof
        for (i, partial) in self.partial_decryption.iter().enumerate() {
            if !partial.verify(&public_key.inner().public_key_proof, &encrypted_vote[i]) {
                return Err(ValidationError::PartialDecryptionProofFailed);
            }
        }

        Ok(())
    }
}

/// Transaction 10: Decryption
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

    /// The contest this decrypted vote is for
    pub contest_index: u32,

    /// The trustees (as defined by index) who's PartialDecryption transactions were used to produce this full decryption
    pub trustees: Vec<u8>,

    /// The decrypted vote
    pub decrypted_vote: Vec<Selection>,
}

impl DecryptionTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        upstream_id: Identifier,
        contest_index: u32,
        upstream_index: u16,
        trustees: Vec<u8>,
        decrypted_vote: Vec<Selection>,
    ) -> DecryptionTransaction {
        debug_assert!(election_id.election_id == upstream_id.election_id);
        // TODO: Debug asserts: upstream_id composition matches contest_index and upstream_index

        DecryptionTransaction {
            id: Self::build_id(election_id, upstream_id, contest_index, upstream_index),
            election_id,
            upstream_id,
            contest_index,
            upstream_index,
            trustees,
            decrypted_vote,
        }
    }

    pub fn build_id(
        election_id: Identifier,
        upstream_id: Identifier,
        contest_index: u32,
        upstream_index: u16,
    ) -> Identifier {
        // The identifier is just the same as the partial-decryptions, except doesn't have trustees
        let unique_info = build_unique_info(upstream_id, contest_index, upstream_index, 0);
        Identifier::new(election_id, TransactionType::Decryption, Some(unique_info))
    }
}

impl CryptoBallotTransaction for DecryptionTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    /// TODO: Any trustee
    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        None
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election_id
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::Decryption
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        // Check the ID
        if Self::build_id(
            self.election_id,
            self.upstream_id,
            self.contest_index,
            self.upstream_index,
        ) != self.id
        {
            return Err(ValidationError::IdentifierBadComposition);
        }

        let election = store.get_election(self.election_id)?;

        // Get the ciphertext either from the vote or the mix
        let encrypted_vote: Vec<Ciphertext> = encrypted_vote_from_upstream_tx(
            store,
            self.upstream_id,
            self.upstream_index,
            self.contest_index,
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
            // TODO: This could be more efficient with a range
            let trustee = election
                .inner()
                .get_trustee(*trustee_index)
                .ok_or(ValidationError::TrusteeDoesNotExist(*trustee_index))?;
            let partial_id = PartialDecryptionTransaction::build_id(
                self.election_id,
                self.upstream_id,
                self.contest_index,
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
        let decrypted_vote = decrypt_vote(
            &encrypted_vote,
            election.inner().trustees_threshold,
            &election.inner().trustees,
            &pubkeys,
            &partials,
        )?;

        if decrypted_vote != self.decrypted_vote {
            return Err(ValidationError::VoteDecryptionMismatch);
        }

        // TODO: Check that the selections match the ballot-style settings

        Ok(())
    }
}

/// Decrypt the vote from the given partial decryptions.
pub fn decrypt_vote(
    ciphertexts: &[Ciphertext],
    trustees_threshold: u8,
    trustees: &[Trustee],
    pubkeys: &[KeyGenPublicKeyTransaction],
    partials: &[PartialDecryptionTransaction],
) -> Result<Vec<Selection>, ValidationError> {
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
    let mut results = Vec::with_capacity(ciphertexts.len());
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let mut decrypt =
            cryptid::threshold::Decryption::new(trustees_threshold as usize, ciphertext);

        for trustee in trustees {
            if let Some(partial) = partials.get(&trustee.index) {
                if let Some(pubkey) = pubkeys.get(&trustee.index) {
                    decrypt.add_share(
                        trustee.index as usize,
                        &pubkey.public_key_proof,
                        &partial.partial_decryption[i],
                    );
                }
            };
        }

        let raw_selection = decrypt
            .finish()
            .map_err(|e| ValidationError::VoteDecryptionFailed(e))?;

        let selection = Selection::decode(raw_selection.as_slice())?;
        results.push(selection);
    }

    Ok(results)
}

/// A convenience function for getting an encrypted-vote from some upstream transaction ID.
/// The upstream transaction should either be a mixnet or a vote transaction.
pub fn encrypted_vote_from_upstream_tx<S: Store>(
    store: &S,
    upstream_id: Identifier,
    upstream_index: u16,
    contest_index: u32,
    mix_config: &Option<MixConfig>,
) -> Result<Vec<Ciphertext>, ValidationError> {
    // Get the ciphertext either from the vote or the mix
    let selections: Vec<Ciphertext> = match upstream_id.transaction_type {
        TransactionType::Vote => {
            if mix_config.is_some() {
                return Err(ValidationError::InvalidUpstreamID);
            }
            if upstream_index != 0 {
                return Err(ValidationError::InvalidUpstreamIndex);
            }

            let vote = store.get_vote(upstream_id)?.tx;

            for encrypted_vote in vote.encrypted_votes {
                if encrypted_vote.contest_index == contest_index {
                    return Ok(encrypted_vote.selections);
                }
            }
            return Err(ValidationError::InvalidUpstreamContestIndex);
        }
        TransactionType::Mix => {
            let mix = store.get_mix(upstream_id)?.tx;

            if mix.contest_index != contest_index {
                return Err(ValidationError::InvalidUpstreamContestIndex);
            }

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

    Ok(selections)
}

// Both partial-decryption and decryption transaction build their unique info the same way
fn build_unique_info(
    upstream_id: Identifier,
    contest_index: u32,
    upstream_index: u16,
    trustee_index: u8,
) -> [u8; 16] {
    let upstream_index = upstream_index.to_be_bytes();
    let contest_index = contest_index.to_be_bytes();

    let mut unique_info = [0; 16];
    unique_info[0..4].copy_from_slice(&contest_index[..]); // 4 bytes
    unique_info[4] = upstream_id.transaction_type.into(); // 1 byte

    if upstream_id.transaction_type == TransactionType::Mix {
        unique_info[5..13].copy_from_slice(&upstream_id.unique_info[4..12]); // 8 bytes
        unique_info[13..15].copy_from_slice(&upstream_index); // 2 bytes
        unique_info[15] = trustee_index; // 1 byte

        // Result:                       [          Lifted From the Mix ID                   ]
        // <contest-index><upstream-type>[<batch-index><mix-index><trustee-index><null-bytes>]<upstream-index><trustee-index>
        //     4 byte          1 bytes      4 bytes     1 byte      1 byte         2 bytes       2 bytes        1 byte
    }
    if upstream_id.transaction_type == TransactionType::Vote {
        unique_info[5..=14].copy_from_slice(&upstream_id.unique_info[..10]); // 10 bytes
        unique_info[15] = trustee_index; // 1 byte

        // Result:
        // <contest-index><upstream-type><voter-public-key><trustee-index>
        //      4 bytes       1 byte         10 bytes          1 byte
    }

    unique_info
}
