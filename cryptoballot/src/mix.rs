use crate::*;
use cryptid::commit::PedersenCtx;
use cryptid::elgamal::Ciphertext;
use cryptid::elgamal::PublicKey as EncryptionPublicKey;
use cryptid::shuffle::{Shuffle, ShuffleProof};
use ed25519_dalek::PublicKey;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Clone)]
pub struct MixConfig {
    pub timeout_secs: u64,
    pub batch_size: Option<u16>,
}

/// Transaction 8: Mix
#[derive(Serialize, Deserialize, Clone)]
pub struct MixTransaction {
    pub id: Identifier,

    /// Election ID
    pub election_id: Identifier,

    /// The previous mix ID, or None if this is the first mix
    pub prev_mix_id: Option<Identifier>,

    /// The trustee index
    pub trustee_index: u8,

    /// The trustee public-key
    #[serde(with = "EdPublicKeyHex")]
    pub trustee_public_key: PublicKey,

    /// The mix-index (starts at 0)
    /// Generally this is the same as the trustee index - 1, but may be different if one of the trustees
    /// failed to produce a mix within the alloted timeout.
    pub mix_index: u8,

    /// The contest that this mix is for
    pub contest_index: u32,

    /// If there are more votes in the contest than the mix batch-size, then mixes are batched
    pub batch: u32,

    /// A list of all vote ids in this mix
    /// These votes-ids must be in ascending order
    pub vote_ids: Vec<Identifier>,

    /// A shuffled and re-encrypted mix of ciphertexts
    pub mixed_ciphertexts: Vec<Ciphertext>,

    /// Proof of correct shuffle and re-encryption
    pub proof: ShuffleProof,
}

impl MixTransaction {
    /// Create a new DecryptionTransaction with the decrypted vote
    pub fn new(
        election_id: Identifier,
        prev_mix_id: Option<Identifier>,
        trustee: &Trustee,
        mix_index: u8,
        contest_index: u32,
        batch: u32,
        vote_ids: Vec<Identifier>,
        mixed_ciphertexts: Vec<Ciphertext>,
        proof: ShuffleProof,
    ) -> Self {
        MixTransaction {
            id: MixTransaction::build_id(
                election_id,
                contest_index,
                batch,
                mix_index,
                trustee.index,
            ),
            election_id,
            prev_mix_id,
            trustee_index: trustee.index,
            trustee_public_key: trustee.public_key,
            mix_index,
            contest_index,
            batch,
            vote_ids,
            mixed_ciphertexts,
            proof,
        }
    }

    // Has an ID format of <election-id><tx-type><contest-index><batch><mix-index><trustee-index>
    pub fn build_id(
        election_id: Identifier,
        contest_index: u32,
        batch: u32,
        mix_index: u8,
        trustee_index: u8,
    ) -> Identifier {
        let contest_index = contest_index.to_be_bytes();
        let batch = batch.to_be_bytes();

        let mut unique_info = [0; 16];
        unique_info[0..4].copy_from_slice(&contest_index); // 4 bytes
        unique_info[4..8].copy_from_slice(&batch); // 4 bytes
        unique_info[8] = mix_index; // 1 byte
        unique_info[9] = trustee_index; // 1 byte

        // Only 10 bytes used (6 NULL bytes left-over at the end)
        // NOTE: Can only ever use a max of 12 bytes here given the construction of PartialDecryption ID And Decryption ID

        Identifier::new(election_id, TransactionType::Mix, Some(unique_info))
    }
}

impl CryptoBallotTransaction for MixTransaction {
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
        TransactionType::Mix
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        // Check the ID
        if Self::build_id(
            self.election_id,
            self.contest_index,
            self.batch,
            self.mix_index,
            self.trustee_index,
        ) != self.id
        {
            return Err(ValidationError::IdentifierBadComposition);
        }

        // Load the election transaction
        let election = store.get_election(self.election_id)?.tx;

        // If there's no mixnet config, then we can't post mixnet transactions
        if election.mix_config.is_none() {
            return Err(ValidationError::NoMixnetConfig);
        }

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

        // TODO: Deal with timeouts and mix index orderings
        if self.mix_index != self.trustee_index - 1 {
            return Err(ValidationError::OutOfOrderMix);
        }

        // Make sure we have all the ciphertexts in the mix
        if self.mixed_ciphertexts.len() != self.vote_ids.len() {
            return Err(ValidationError::MixWrongNumberOfVotes);
        }

        let input_ciphertexts = if self.prev_mix_id.is_some() {
            let prev_mix: MixTransaction = store
                .get_transaction(self.prev_mix_id.unwrap())
                .ok_or(ValidationError::MissingPrevMixTransaction)?
                .into();

            // Make sure this is the correct previous mix
            if self.mix_index != prev_mix.mix_index + 1
                || self.election_id != prev_mix.election_id
                || self.contest_index != prev_mix.contest_index
                || self.batch != prev_mix.batch
                || self.vote_ids != prev_mix.vote_ids
            {
                return Err(ValidationError::InvalidPrevMixTransaction);
            }

            prev_mix.mixed_ciphertexts
        } else {
            if self.mix_index != 0 {
                return Err(ValidationError::OutOfOrderMix);
            }

            // Check that vote-ids are in ascending order with no duplicates
            // TODO: Do this in a single function, I think we can use "is_sorted_by" to disallow equalities
            if !&self.vote_ids.is_sorted() {
                return Err(ValidationError::MixVoteIdsNotSorted);
            }
            if !has_unique_elements(self.vote_ids.iter()) {
                return Err(ValidationError::MixVoteIdsNotSorted);
            }

            // TODO: Support batching
            //       - Check that vote_ids.len() <= batch-size
            //       - Validate batching - make sure batched votes are exactly correct
            //       - This will require reading the votes in order and checking for first, or ranging off the final vote_ids of prev mix

            // Make sure all votes are accounted for
            let votes = store.range(
                Identifier::start(self.election_id, TransactionType::Vote, None),
                Identifier::end(self.election_id, TransactionType::Vote, None),
            );

            if votes.len() != self.vote_ids.len() {
                return Err(ValidationError::MixWrongNumberOfVotes);
            }

            for (i, vote) in votes.iter().enumerate() {
                if self.vote_ids[i] != vote.id() {
                    return Err(ValidationError::MixVotesNotAccountedFor);
                }
            }

            let mut ciphertexts = Vec::with_capacity(self.vote_ids.len());
            for vote in votes {
                let vote: VoteTransaction = vote.into();

                for encrypted_vote in vote.encrypted_votes {
                    if encrypted_vote.contest_index == self.contest_index {
                        ciphertexts.push(encrypted_vote.ciphertext);
                    }
                }
            }

            ciphertexts
        };

        let enc_key_tx = Identifier::new(self.election_id, TransactionType::EncryptionKey, None);
        let key_tx: EncryptionKeyTransaction = store
            .get_transaction(enc_key_tx)
            .ok_or(ValidationError::EncryptionKeyTransactionDoesNotExist)?
            .into();

        // Verify that the mix is correct
        verify_mix(
            input_ciphertexts,
            self.mixed_ciphertexts.clone(),
            &key_tx.encryption_key,
            &self.proof,
            self.trustee_index,
            self.mix_index,
            self.contest_index,
            self.batch,
        )?;

        Ok(())
    }
}

/// Do a mixnet shuffle
/// This is an expensive and time-consuming operation, so should ideally be offloaded to it's own thread
pub fn mix<R: Rng + CryptoRng>(
    rng: &mut R,
    ciphertexts: Vec<Ciphertext>,
    encryption_key: &EncryptionPublicKey,
    trustee_index: u8,
    mix_index: u8,
    contest_index: u32,
    batch: u32,
) -> Result<(Vec<Ciphertext>, ShuffleProof), Error> {
    let seed = generate_pedersen_seed(trustee_index, mix_index, contest_index, batch);
    let (commit_ctx, generators) = PedersenCtx::with_generators(&seed, ciphertexts.len());

    let shuffle =
        Shuffle::new(rng, vec![ciphertexts], encryption_key).map_err(|e| Error::ShuffleError(e))?;

    let proof = shuffle
        .gen_proof(rng, &commit_ctx, &generators, encryption_key)
        .map_err(|e| Error::ShuffleError(e))?;

    let output = shuffle
        .into_outputs()
        .pop()
        .expect("Missing expected re-encrypted ciphertexts");
    Ok((output, proof))
}

/// Verify mixnet shuffle
pub fn verify_mix(
    input_ciphertexts: Vec<Ciphertext>,
    output_ciphertexts: Vec<Ciphertext>,
    encryption_key: &EncryptionPublicKey,
    proof: &ShuffleProof,
    trustee_index: u8,
    mix_index: u8,
    contest_index: u32,
    batch: u32,
) -> Result<(), ValidationError> {
    let seed = generate_pedersen_seed(trustee_index, mix_index, contest_index, batch);
    let (commit_ctx, generators) = PedersenCtx::with_generators(&seed, input_ciphertexts.len());

    if !proof.verify(
        &commit_ctx,
        &generators,
        &vec![input_ciphertexts],
        &vec![output_ciphertexts],
        encryption_key,
    ) {
        return Err(ValidationError::ShuffleVerificationFailed);
    }

    Ok(())
}

fn generate_pedersen_seed(
    trustee_index: u8,
    mix_index: u8,
    contest_index: u32,
    batch: u32,
) -> Vec<u8> {
    let mut seed = vec![trustee_index, mix_index];
    seed.extend_from_slice(&contest_index.to_be_bytes());
    seed.extend_from_slice(&batch.to_be_bytes());

    seed
}

fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + std::hash::Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}
