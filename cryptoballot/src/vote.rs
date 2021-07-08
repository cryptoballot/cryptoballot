use crate::*;
use cryptid::elgamal::Ciphertext;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

/// Transaction 6: Vote
///
/// A vote transaction is posted by the voter, and contains their encrypted vote for the contests defined by a ballot.
///
/// The vote contains no idenifying information about the voter, allowing them to vote anonymously.
///
/// Before a voter can post a VoteTransaction, they must first be authenticated by a quorum of authenticator,
/// who certify that they can vote this election and ballot.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VoteTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub ballot_id: String,

    pub encrypted_votes: Vec<EncryptedVote>,

    /// The public key used to anonymized the voter.
    /// The voter should not reveal that they own this key - doing so will leak their real identity.
    #[serde(with = "EdPublicKeyHex")]
    pub anonymous_key: PublicKey,

    /// A set of authentications, certifying that the anonymous_key provided can vote this election and ballot.
    pub authentication: Vec<Authentication>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedVote {
    pub contest_index: u32,
    pub selections: Vec<Ciphertext>,
}

impl VoteTransaction {
    /// Create a new vote transaction.
    pub fn new(
        election_id: Identifier,
        ballot_id: String,
        encrypted_votes: Vec<EncryptedVote>,
    ) -> (Self, SecretKey) {
        let (secret_key, public_key) = generate_keypair();

        let vote = VoteTransaction {
            id: Self::build_id(election_id, &public_key),
            election: election_id,
            ballot_id: ballot_id,
            encrypted_votes,
            anonymous_key: public_key,
            authentication: vec![],
        };

        (vote, secret_key)
    }

    pub fn build_id(election_id: Identifier, public_key: &PublicKey) -> Identifier {
        let unique_info = public_key.as_bytes();
        Identifier::new(
            election_id,
            TransactionType::Vote,
            Some(unique_info[0..16].try_into().unwrap()),
        )
    }
}

impl CryptoBallotTransaction for VoteTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.anonymous_key)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.election
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::Vote
    }

    /// Validate the vote transaction
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        // Check the ID
        if Self::build_id(self.election, &self.anonymous_key) != self.id {
            return Err(ValidationError::IdentifierBadComposition);
        }

        let election = store.get_election(self.election)?;

        // Anonymous key may not share the first 80 bits (10 bytes) with any other vote transaction
        //       Probability is EXCEEDINGLY rare (About 1 in a septillion) for a random happening
        //       But it could also happen maliciously on purpose, so we need to check
        let unique_info_mask = &self.anonymous_key.as_bytes()[0..10];
        let start_collision =
            Identifier::start(self.election, TransactionType::Vote, Some(unique_info_mask));
        let end_collision =
            Identifier::start(self.election, TransactionType::Vote, Some(unique_info_mask));
        if store.range(start_collision, end_collision).len() > 0 {
            return Err(ValidationError::VoteAnonymousKeyCollision);
        }

        // Validate that there is a EncryptionKeyTransaction
        let enc_key_tx = Identifier::new(self.election, TransactionType::EncryptionKey, None);
        if store.get_transaction(enc_key_tx).is_none() {
            return Err(ValidationError::EncryptionKeyTransactionDoesNotExist);
        }

        // Validate that there isn't a VotingEnd Transactipn
        let enc_key_tx = Identifier::new(self.election, TransactionType::VotingEnd, None);
        if store.get_transaction(enc_key_tx).is_some() {
            return Err(ValidationError::VotingHasEnded);
        }

        // TODO: minimum authentication needed to be defined in election
        for authn in self.authentication.iter() {
            let authenticator = election
                .get_authenticator(authn.authenticator)
                .ok_or(ValidationError::AuthDoesNotExist)?;

            authenticator
                .verify(
                    election.id,
                    &self.ballot_id,
                    &self.anonymous_key,
                    &authn.signature,
                )
                .map_err(|_| ValidationError::AuthFailed)?;
        }

        let ballot = match election.get_ballot(&self.ballot_id) {
            Some(ballot) => ballot,
            None => return Err(ValidationError::BallotDoesNotExist),
        };

        // Verify that the voter has only voted in contests for which they are authorized
        for encrypted_vote in &self.encrypted_votes {
            if !ballot.contests.contains(&encrypted_vote.contest_index) {
                return Err(ValidationError::VotedInWrongContest);
            }
        }

        Ok(())
    }
}

/// Encrypt a vote with the public key provided by the encryption_key transaction (EncryptionKeyTransaction.encryption_key)
pub fn encrypt_vote<R: CryptoRng + RngCore>(
    encryption_key: &cryptid::elgamal::PublicKey,
    vote: Vec<Selection>,
    rng: &mut R,
) -> Result<Vec<cryptid::elgamal::Ciphertext>, Error> {
    let mut results = Vec::with_capacity(vote.len());
    for selection in vote {
        let mut buf = Vec::with_capacity(selection.encoded_len());
        selection.encode(&mut buf)?;
        results.push(encryption_key.encrypt(rng, &buf))
    }

    Ok(results)
}
