use crate::*;
use ed25519_dalek::PublicKey;
use sharks::Sharks;
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

    /// Election public key for encrypting votes. It is an uncompressed `secp256k1::PublicKey`.
    ///
    /// This public key is used to encrypt all votes using ECIES encryption. This keeps
    /// all the votes secret until the trustees post SecretShare transaction to allow
    /// decryption of the voters after the election is over.
    ///
    /// After generating the keypair, the secret should be distributed to the trustees using
    /// Shamir Secret Sharing and then destroyed.
    ///
    /// Future plans include moving to Distributed key generation, so no one entity ever has
    /// the secret key, even temporarily.
    #[serde(with = "hex_serde")]
    pub encryption_public: Vec<u8>,

    /// List of ballots that can be cast in this election
    // TODO: Define ballot struct
    pub ballots: Vec<uuid::Uuid>,

    /// List of trustees that have been given a secret key share
    pub trustees: Vec<Trustee>,

    /// Minimum number of trustees needed to reconstruct the secret key and decrypt votes.
    pub trustees_threshold: u8,

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
    pub fn new(authority_public: PublicKey) -> (Self, secp256k1::SecretKey) {
        let (secret, public) = ecies::utils::generate_keypair();

        let election = ElectionTransaction {
            id: Identifier::new_for_election(),
            authority_public: authority_public,
            encryption_public: public.serialize().to_vec(),
            ballots: vec![],
            trustees: vec![],
            trustees_threshold: 1,
            authenticators: vec![],
            authenticators_threshold: 1,
        };

        (election, secret)
    }

    /// Validate the election transaction
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Make sure the encryption public-key is well-formed
        if self.encryption_public.len() != 65 {
            return Err(ValidationError::InvalidPublicKey);
        }
        // TODO: check parsing of public key

        // Make sure trustees settings are sane
        if self.trustees_threshold > self.trustees.len() as u8 {
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
}

/// Deal the election secret into shares, ready to be distributed to trustees.
///
/// Generally the election authority will generate the secret, distribute it to trustees, then destroy
/// the secret.
///
/// Future plans include moving to distributed key generation, removing all centralized control of the
/// secret key.
pub fn deal_secret_shares(theshold: u8, num_trustees: usize, secret: &[u8]) -> Vec<Vec<u8>> {
    let sharks = Sharks(theshold);
    let dealer = sharks.dealer(secret);

    let mut all_shares = Vec::with_capacity(num_trustees);
    for s in dealer.take(num_trustees) {
        all_shares.push(Vec::from(&s));
    }

    all_shares
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn create_new_election() {
        let (_authority_secret, authority_public) = generate_keypair();

        let (mut election, _election_secret) = ElectionTransaction::new(authority_public);

        // Create a trustee and add it to the election
        let (trustee, _trustee_secret) = Trustee::new();
        election.trustees.push(trustee);

        // Create an authenticator and add it to the election
        let ballot_id = Uuid::new_v4();
        let (authn, _authn_secrets) = Authenticator::new(256, &vec![ballot_id]).unwrap();
        election.authenticators.push(authn);

        // Verify the election transaction
        election.validate().expect("Election did not verify");
    }
}
