use crate::EncryptionKeyTransaction;
use crate::Error;
use crate::Identifier;
use crate::Signable;
use crate::Store;
use crate::TransactionType;
use crate::Trustee;
use crate::ValidationError;
use cryptid::commit::PedersenCtx;
use cryptid::elgamal::Ciphertext;
use cryptid::elgamal::PublicKey as EncryptionPublicKey;
use cryptid::shuffle::{Shuffle, ShuffleProof};
use ed25519_dalek::PublicKey;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct MixConfig {
    pub timeout_secs: u64,
    pub min_shuffles: u8,
    pub batch_size: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MixTransaction {
    pub id: Identifier,

    /// Election ID
    pub election_id: Identifier,

    /// The previous mix ID, or None if this is the first mix
    pub prev_mix_id: Option<Identifier>,

    /// The ID of the trustee producing this mix transaction
    pub trustee_id: Uuid,

    /// The trustee index
    pub trustee_index: u8,

    /// The trustee public-key
    pub trustee_public_key: PublicKey,

    /// The mix-index (starts at 1)
    /// Generally this is the same as the trustee index, but may be different if one of the trustees
    /// failed to produce a mix within the alloted timeout.
    pub mix_index: u8,

    /// The contest that this mix is for
    pub contest_index: u64,

    /// If there are more votes in the contest than the mix batch-size, then mixes are batched
    pub batch: u64,

    /// A list of all vote ids in this mix
    /// These votes-ids must be in ascending order
    pub vote_ids: Vec<Identifier>,

    /// A shuffled and re-encrypted mix of ciphertexts
    pub reencryption: Vec<Ciphertext>,

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
        contest_index: u64,
        batch: u64,
        vote_ids: Vec<Identifier>,
        reencryption: Vec<Ciphertext>,
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
            trustee_id: trustee.id,
            trustee_index: trustee.index,
            trustee_public_key: trustee.public_key,
            mix_index,
            contest_index,
            batch,
            vote_ids,
            reencryption,
            proof,
        }
    }

    // Has an ID format of <election-id><tx-type><contest-index><batch><mix-index><trustee-index>
    pub fn build_id(
        election_id: Identifier,
        contest_index: u64,
        batch: u64,
        mix_index: u8,
        trustee_index: u8,
    ) -> Identifier {
        let contest_index = contest_index.to_be_bytes(); // 4 bytes
        let batch = batch.to_be_bytes(); // 4 bytes

        let mut unique_info = [0; 16];
        unique_info[0..4].copy_from_slice(&contest_index);
        unique_info[4..8].copy_from_slice(&batch);
        unique_info[8] = mix_index;
        unique_info[9] = trustee_index;
        // 6 NULL bytes left-over at the end

        Identifier::new(election_id, TransactionType::Mix, &unique_info)
    }
}

impl Signable for MixTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.trustee_public_key)
    }

    fn inputs(&self) -> Vec<Identifier> {
        vec![self.election_id]
    }

    /// Validate the transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        let election = store.get_election(self.election_id)?.tx;

        // If there's no mixnet config, then we can't post mixnet transactions
        if election.mixnet.is_none() {
            return Err(ValidationError::NoMixnetConfig);
        }

        // Validate that this trustee exists
        let mut trustee_exists = false;
        for trustee in &election.trustees {
            if trustee.id == self.trustee_id
                && trustee.public_key == self.trustee_public_key
                && trustee.index == self.trustee_index
            {
                trustee_exists = true;
            }
        }
        if !trustee_exists {
            return Err(ValidationError::TrusteeDoesNotExist(self.trustee_id));
        }

        // TODO: Deal with timeouts and mix index orderings
        if self.mix_index != self.trustee_index {
            return Err(ValidationError::OutOfOrderMix);
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

            prev_mix.reencryption
        } else {
            if self.mix_index != 1 {
                return Err(ValidationError::OutOfOrderMix);
            }

            // Check that vote-ids are in ascending order
            if !&self.vote_ids.is_sorted() {
                return Err(ValidationError::MixVoteIdsNotSorted);
            }

            // TODO: Check that vote_ids.len() <= batch-size
            // TODO: Validate batching - make sure batched votes are exactly correct
            // This will require reading the votes in order and checking for first, or ranging off the final vote_ids of prev mix

            let mut vote_txs = Vec::with_capacity(self.vote_ids.len());
            for vote_id in &self.vote_ids {
                vote_txs.push(store.get_vote(*vote_id)?.tx.encrypted_vote);
            }

            vote_txs
        };

        let enc_key_tx =
            Identifier::new(self.election_id, TransactionType::EncryptionKey, &[0; 16]);
        let key_tx: EncryptionKeyTransaction = store
            .get_transaction(enc_key_tx)
            .ok_or(ValidationError::EncryptionKeyTransactionDoesNotExist)?
            .into();

        // Verify that the shuffle is correct
        verify_shuffle(
            input_ciphertexts,
            self.reencryption.clone(),
            &key_tx.encryption_key,
            &self.proof,
            self.trustee_id,
            self.mix_index,
            self.contest_index,
            self.batch,
        )?;

        Ok(())
    }
}

/// Do a mixnet shuffle
/// This is an expensive and time-consuming operation, so should ideally be offloaded to it's own thread
pub fn shuffle<R: Rng + CryptoRng>(
    rng: &mut R,
    ciphertexts: Vec<Ciphertext>,
    encryption_key: &EncryptionPublicKey,
    trustee_id: Uuid,
    mix_index: u8,
    contest_index: u64,
    batch: u64,
) -> Result<(Vec<Ciphertext>, ShuffleProof), Error> {
    let seed = generate_pedersen_seed(trustee_id, mix_index, contest_index, batch);
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
pub fn verify_shuffle(
    input_ciphertexts: Vec<Ciphertext>,
    output_ciphertexts: Vec<Ciphertext>,
    encryption_key: &EncryptionPublicKey,
    proof: &ShuffleProof,
    trustee_id: Uuid,
    mix_index: u8,
    contest_index: u64,
    batch: u64,
) -> Result<(), ValidationError> {
    let seed = generate_pedersen_seed(trustee_id, mix_index, contest_index, batch);
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
    trustee_id: Uuid,
    mix_index: u8,
    contest_index: u64,
    batch: u64,
) -> Vec<u8> {
    let mut seed = trustee_id.as_bytes().to_vec();
    seed.extend_from_slice(&[mix_index]);
    seed.extend_from_slice(&contest_index.to_be_bytes());
    seed.extend_from_slice(&batch.to_be_bytes());

    seed
}
