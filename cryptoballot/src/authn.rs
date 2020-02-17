use crate::*;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct Authenticator {
    pub id: uuid::Uuid,
    pub public_key: PublicKey,
    // TODO: Enum of type of auth provided.
    // pub auth_type: AuthType,
}

impl Authenticator {
    pub fn new() -> (Self, SecretKey) {
        let (secret, public) = generate_keypair();
        let authenticator = Authenticator {
            id: Uuid::new_v4(),
            public_key: public,
        };
        return (authenticator, secret);
    }

    pub fn authenticate(
        &self,
        secret: &SecretKey,
        election_id: Identifier,
        ballot_id: Uuid,
        voter_public_key: &PublicKey,
    ) -> Authentication {
        let package = AuthPackage {
            election_id,
            ballot_id,
            voter_public_key: voter_public_key.clone(),
        };
        let serialized = serde_cbor::to_vec(&package).expect("cryptoballot: Unable to serialize");

        let expanded: ExpandedSecretKey = secret.into();
        let signature = expanded.sign(&serialized, &self.public_key);
        let authentication = Authentication {
            authenticator: self.id,
            signature: signature,
        };

        authentication
    }

    pub fn verify(
        &self,
        election_id: Identifier,
        ballot_id: Uuid,
        voter_public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Error> {
        let package = AuthPackage {
            election_id,
            ballot_id,
            voter_public_key: voter_public_key.clone(),
        };
        let serialized = serde_cbor::to_vec(&package).expect("cryptoballot: Serialization failure");

        Ok(self.public_key.verify_strict(&serialized, signature)?)
    }
}

// TODO: Be smarter about lifetimes here so we don't need to clone PublicKey
#[derive(Serialize, Deserialize, Clone)]
struct AuthPackage {
    election_id: Identifier,
    ballot_id: Uuid,
    voter_public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {
    pub authenticator: Uuid,
    pub signature: Signature,
}
