use crate::authn::*;
use ed25519_dalek::Keypair;
use ed25519_dalek::SecretKey;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct ElectionTransaction {
    pub id: Uuid,

    // secp256k1::PublicKey, uncompressed
    pub public_key: Vec<u8>,

    pub authenticators: Vec<Authenticator>,
    pub ballots: Vec<uuid::Uuid>, //TODO: Define ballot struct
    pub features: Vec<Feature>,

    // Optional feature-based fields
    pub re_encryption_mixnet: Option<ReEncryptionMixnet>,
    pub threshhold_decryption: Option<ThresholdDecryption>,
}

impl ElectionTransaction {
    /// Check if the election has the given feature
    pub fn has_feature(&self, feature: Feature) -> bool {
        for feat in self.features.iter() {
            if feature == *feat {
                return true;
            }
        }
        return false;
    }

    pub fn validate(&self) -> Result<(), ()> {
        // Make sure the public-key is well-formed
        if self.public_key.len() != 65 {
            // TODO: return error
        }
        // TODO check parsing

        // Make sure threshold-decryption parameters are sane
        if self.has_feature(Feature::ThresholdDecryption) {
            let threshhold_decryption = self.threshhold_decryption.as_ref().ok_or(())?;

            if threshhold_decryption.threshold == 0 {
                // return error
            }
            if threshhold_decryption.threshold as usize > threshhold_decryption.trustees.len() {
                // TODO: return error
            }
        }
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

    pub fn get_authenticatort(&self, authn_id: Uuid) -> Option<&Authenticator> {
        for authn in self.authenticators.iter() {
            if authn_id == authn.id {
                return Some(authn);
            }
        }
        None
    }
}

impl Default for ElectionTransaction {
    fn default() -> Self {
        return ElectionTransaction {
            id: Uuid::new_v4(),
            public_key: vec![],
            authenticators: vec![],
            ballots: vec![],
            features: vec![],
            re_encryption_mixnet: None,
            threshhold_decryption: None,
        };
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Feature {
    ReEncryptionMixnet,
    ThresholdDecryption,
    HomomorphicTally,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ReEncryptionMixnet {
    mixers: Vec<Mixer>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ThresholdDecryption {
    threshold: u8,
    trustees: Vec<Trustee>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Trustee {
    pub id: uuid::Uuid,
    pub public_key: [u8; 32],
}

impl Trustee {
    pub fn new() -> (Self, SecretKey) {
        let mut csprng = rand::rngs::OsRng {};

        let Keypair {
            public: trustee_public,
            secret: trustee_secret,
        } = Keypair::generate(&mut csprng);

        let trustee = Trustee {
            id: Uuid::new_v4(),
            public_key: trustee_public.to_bytes(),
        };
        return (trustee, trustee_secret);
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Mixer {
    pub id: uuid::Uuid,
    pub public_key: [u8; 32],
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn create_new_election() {
        let mut election = ElectionTransaction::default();

        // Create a trustee and add it to the election
        let (trustee, _trustee_secret) = Trustee::new();
        election.features.push(Feature::ThresholdDecryption);
        election.threshhold_decryption = Some(ThresholdDecryption {
            threshold: 1,
            trustees: vec![trustee],
        });

        // Verify the election transaction
        election.validate().expect("Election did not verify");
    }
}
