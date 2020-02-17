use crate::*;
use ed25519_dalek::PublicKey;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct ElectionTransaction {
    pub id: Identifier,

    /// Election authority PublicKey
    pub authority_public: PublicKey,

    /// Election public key for encrypting votes
    /// secp256k1::PublicKey, uncompressed
    pub encryption_public: Vec<u8>,

    // List of ballots that can be cast in this election
    // TODO: Define ballot struct
    pub ballots: Vec<uuid::Uuid>,

    // Trustees
    pub trustees: Vec<Trustee>,
    pub trustees_threshold: u8,

    // Authenticators
    pub authenticators: Vec<Authenticator>,
    pub authenticators_threshold: u8,
}

impl ElectionTransaction {
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

        Ok(())
    }

    // TODO: return a ballot struct when we have it defined
    pub fn get_ballot(&self, ballot_id: Uuid) -> Option<()> {
        for ballot in self.ballots.iter() {
            if ballot_id == *ballot {
                return Some(());
            }
        }
        None
    }

    pub fn get_authenticator(&self, authn_id: Uuid) -> Option<&Authenticator> {
        for authn in self.authenticators.iter() {
            if authn_id == authn.id {
                return Some(authn);
            }
        }
        None
    }

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

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        None
    }
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
        let (authn, _authn_secret) = Authenticator::new(256).unwrap();
        election.authenticators.push(authn);

        // Verify the election transaction
        election.validate().expect("Election did not verify");
    }
}
