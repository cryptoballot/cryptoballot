use crate::*;
use ed25519_dalek::PublicKey;
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

    /// List of ballots that can be cast in this election
    // TODO: Define ballot struct
    pub ballots: Vec<uuid::Uuid>,

    /// List of trustees that have been given a secret key share
    pub trustees: Vec<Trustee>,

    /// Minimum number of trustees needed to reconstruct the secret key and decrypt votes.
    pub trustees_threshold: usize,

    /// Authenticators who can authenticate voters
    pub authenticators: Vec<Authenticator>,

    /// Mininum number of authenticators that might provide a signature for a voter
    /// for that voter to post a Vote transaction.
    pub authenticators_threshold: u8,
}

impl ElectionTransaction {
    /// Create a new ElectionTransaction
    ///
    /// The returned SecretKey should be distributed to the trustees using Shamir Secret Sharing
    pub fn new(authority_public: PublicKey) -> Self {
        ElectionTransaction {
            id: Identifier::new_for_election(),
            authority_public: authority_public,
            ballots: vec![],
            trustees: vec![],
            trustees_threshold: 1,
            authenticators: vec![],
            authenticators_threshold: 1,
        }
    }

    // TODO: return a ballot struct when we have it defined
    /// Get a ballot with the given ID
    pub fn get_ballot(&self, ballot_id: Uuid) -> Option<()> {
        for ballot in self.ballots.iter() {
            if ballot_id == *ballot {
                return Some(());
            }
        }
        None
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
    pub fn get_trustee(&self, trustee_id: Uuid) -> Option<&Trustee> {
        for trustee in self.trustees.iter() {
            if trustee_id == trustee.id {
                return Some(trustee);
            }
        }
        None
    }
}

impl Signable for ElectionTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    fn public(&self) -> Option<PublicKey> {
        Some(self.authority_public)
    }

    fn inputs(&self) -> Vec<Identifier> {
        // No inputs requires for election
        vec![]
    }

    /// Validate the election transaction
    fn validate_tx<S: Store>(&self, _store: &S) -> Result<(), ValidationError> {
        // TODO: Make sure the encryption public-key is well-formed
        // TODO: check parsing of public key

        // Make sure trustees settings are sane
        if self.trustees_threshold > self.trustees.len() {
            return Err(ValidationError::InvalidTrusteeThreshold);
        }
        // TODO: check that we have at least 1 trustee

        // Make sure authenticator settings are sane
        if self.authenticators_threshold > self.authenticators.len() as u8 {
            return Err(ValidationError::InvalidAuthThreshold);
        }
        // TODO: check that we have at least 1 authenticator

        // TODO: Sanity check ballot-ids in authenticators and ballots listed in election

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
        let ballot_id = Uuid::new_v4();

        // Create an authenticator
        let (authenticator, authn_secrets) = Authenticator::new(256, &vec![ballot_id]).unwrap();
        let _authn_secret = authn_secrets.get(&ballot_id).unwrap();
        let _authn_public = authenticator.public_keys.get(&ballot_id).unwrap().as_ref();

        // Create 1 trustee
        let (trustee, _trustee_secret) = Trustee::new(1, 1, 1);

        // Create an election transaction with a single ballot
        let mut election = ElectionTransaction::new(authority_public);
        election.ballots = vec![ballot_id];

        // Validation should fail without authenticators
        assert!(election.validate_tx(&store).is_err());
        election.authenticators = vec![authenticator.clone()];

        // Validation should fail without trustees
        assert!(election.validate_tx(&store).is_err());
        election.trustees = vec![trustee.clone()];

        // Signing with wrong key should fail
        assert!(Signed::sign(&bad_secret, election.clone()).is_err());

        // Check inputs
        assert!(election.inputs().is_empty());

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

        // Getting non-existent things shouldn't work
        let some_uuid = Uuid::new_v4();
        assert!(election.get_ballot(some_uuid).is_none());
        assert!(election.get_authenticator(some_uuid).is_none());
        assert!(election.get_trustee(some_uuid).is_none());
    }
}
