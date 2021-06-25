use crate::*;
use ed25519_dalek::PublicKey;
use indexmap::IndexMap;
use rand::Rng;
use uuid::Uuid;

/// Transaction 1: Election
#[derive(Serialize, Deserialize, Clone)]
pub struct ElectionTransaction {
    pub id: Identifier,

    /// Election Authority Public Key
    ///
    /// The election authority's public key should be posted in a trusted and well-known location.
    ///
    /// If using sawtooth, before you can post an Election transation,
    /// you must register an Election Authority's public key via `sawset`.
    #[serde(with = "EdPublicKeyHex")]
    pub authority_public: PublicKey,

    /// List of trustees that have been given a secret key share
    pub trustees: Vec<Trustee>,

    /// Minimum number of trustees needed to reconstruct the secret key and decrypt votes.
    /// This is also the number of mixes that will be performed as part of the mixnet
    pub trustees_threshold: u8,

    /// Authenticators who can authenticate voters
    pub authenticators: Vec<Authenticator>,

    /// Mininum number of authenticators that might provide a signature for a voter
    /// for that voter to post a Vote transaction.
    pub authenticators_threshold: u8,

    /// Mixnet configuration, None implies no mix-net
    pub mix_config: Option<MixConfig>,

    /// List of ballots that can be cast in this election
    pub ballots: Vec<Ballot>,

    /// List of contests in this election
    pub contests: Vec<Contest>,

    /// Application specific properties.
    ///
    /// Hashmaps are not allowed because their unstable ordering leads to non-determinism.
    #[serde(default)]
    pub properties: IndexMap<String, serde_json::Value>,
}

impl ElectionTransaction {
    /// Create a new ElectionTransaction
    ///
    /// The returned SecretKey should be distributed to the trustees using Shamir Secret Sharing
    pub fn new(authority_public: PublicKey) -> Self {
        let mut csprng = rand::thread_rng();

        ElectionTransaction {
            id: Self::build_id(csprng.gen()),
            authority_public: authority_public,
            trustees: vec![],
            trustees_threshold: 1,
            authenticators: vec![],
            authenticators_threshold: 1,
            mix_config: None,
            ballots: vec![],
            contests: vec![],
            properties: IndexMap::new(),
        }
    }

    /// Create a new identifier for an election
    pub fn build_id(election_id: [u8; 15]) -> Identifier {
        Identifier {
            election_id,
            transaction_type: TransactionType::Election,
            unique_info: [0; 16],
        }
    }

    /// Get an authenticator with the given ID
    pub fn get_authenticator(&self, authn_id: Uuid) -> Option<&Authenticator> {
        for authn in self.authenticators.iter() {
            if authn_id == authn.id {
                return Some(authn);
            }
        }
        None
    }

    /// Get a trustee with the given ID
    pub fn get_trustee(&self, trustee_index: u8) -> Option<&Trustee> {
        for trustee in self.trustees.iter() {
            if trustee_index == trustee.index {
                return Some(trustee);
            }
        }
        None
    }

    pub fn get_ballot(&self, ballot_id: &str) -> Option<&Ballot> {
        for ballot in &self.ballots {
            if ballot.id == ballot_id {
                return Some(ballot);
            }
        }
        None
    }

    /// Get all trustees with all info
    pub fn get_full_trustees(&self) -> Vec<Trustee> {
        let mut trustees = Vec::with_capacity(self.trustees.len());
        for trustee in self.trustees.iter() {
            let mut trustee = trustee.clone();
            trustee.threshold = self.trustees_threshold;
            trustee.num_trustees = self.trustees.len();
            trustees.push(trustee);
        }
        trustees
    }
}

impl CryptoBallotTransaction for ElectionTransaction {
    #[inline(always)]
    fn id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn public(&self) -> Option<PublicKey> {
        Some(self.authority_public)
    }

    #[inline(always)]
    fn election_id(&self) -> Identifier {
        self.id
    }

    #[inline(always)]
    fn tx_type() -> TransactionType {
        TransactionType::Election
    }

    /// Validate the election transaction
    fn validate_tx<S: Store>(&self, _store: &S) -> Result<(), ValidationError> {
        if Self::build_id(self.id.election_id) != self.id {
            return Err(ValidationError::IdentifierBadComposition);
        }

        // Make sure trustees settings are sane
        if self.trustees_threshold as usize > self.trustees.len() {
            return Err(ValidationError::InvalidTrusteeThreshold);
        }

        // Make sure authenticator settings are sane
        if self.authenticators_threshold > self.authenticators.len() as u8 {
            return Err(ValidationError::InvalidAuthThreshold);
        }

        // TODO: Make sure the encryption public-key is well-formed
        // TODO: check parsing of public key
        // TODO: check that we have at least 1 trustee
        // TODO: Hard Maximum of 255 trustees (index needs to fit in a non-zero u8)
        // TODO: Sanity check ballot-ids in authenticators
        // TODO: MixConfig validation: non-zero on all three params
        // TODO: Check that properties do not contain hashmaps (due to unstable ordering) (including in ballots, contests, and candidates)
        // TODO: Check that ballots and contests are consistent and well formed
        //       All contests must exist in at least one ballot
        //       All ballot contests must exist
        //       All contest and ballots have a unique ID
        //       All contests have a unique index
        //       All candidates have a unique index within their contest

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn create_new_election() {
        let store = MemStore::default();

        // Bad keypair
        let (bad_secret, _bad_public) = generate_keypair();

        // Create election authority public and private key
        let (authority_secret, authority_public) = generate_keypair();

        // Create a ballot (TODO: make this a proper struct)
        let ballot = Ballot {
            id: "TEST".to_string(),
            contests: vec![0],
            properties: IndexMap::new(),
        };

        let contest = Contest {
            index: 0,
            contest_type: ContestType::Plurality,
            num_winners: 1,
            write_in: true,
            candidates: vec![],
            properties: IndexMap::new(),
        };

        // Create an authenticator
        let (authenticator, authn_secrets) =
            Authenticator::new(256, &vec!["TEST".to_string()]).unwrap();
        let _authn_secret = authn_secrets.get(&ballot.id).unwrap();
        let _authn_public = authenticator.public_keys.get(&ballot.id).unwrap().as_ref();

        // Create 1 trustee
        let (trustee, _trustee_secret) = Trustee::new(1, 1, 1);

        // Create an election transaction with a single ballot
        let mut election = ElectionTransaction::new(authority_public);
        election.ballots = vec![ballot];
        election.contests = vec![contest];

        // Validation should fail without authenticators
        assert!(election.validate_tx(&store).is_err());
        election.authenticators = vec![authenticator.clone()];

        // Validation should fail without trustees
        assert!(election.validate_tx(&store).is_err());
        election.trustees = vec![trustee.clone()];

        // Signing with wrong key should fail
        assert!(Signed::sign(&bad_secret, election.clone()).is_err());

        // Turn it into a generic transaction and check some thing
        let election_generic = Transaction::Election(election.clone());
        assert!(election_generic.transaction_type() == TransactionType::Election);
        assert!(election_generic.id() == election.id);

        // Finalize election transaction by signing it
        let election = Signed::sign(&authority_secret, election).unwrap();
        assert!(election.id() == election.id);
        let election_generic = SignedTransaction::Election(election.clone());
        assert!(election_generic.transaction_type() == TransactionType::Election);
        assert_eq!(
            format!("{}", election_generic.transaction_type()),
            "election"
        );
        assert!(election_generic.id() == election.id);

        // Validate the election transaction
        election.verify_signature().unwrap();
        election.validate(&store).unwrap();
        election_generic.validate(&store).unwrap();

        // Getting non-existent things shouldn't work
        let some_uuid = Uuid::new_v4();
        assert!(election.get_authenticator(some_uuid).is_none());
        assert!(election.get_trustee(0).is_none());
        assert!(election.get_trustee(2).is_none());
    }
}
