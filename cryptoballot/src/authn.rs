use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::Keypair;
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
        let mut csprng = rand::rngs::OsRng {};

        let Keypair {
            public: auth_public,
            secret: auth_secret,
        } = Keypair::generate(&mut csprng);

        let authenticator = Authenticator {
            id: Uuid::new_v4(),
            public_key: auth_public,
        };
        return (authenticator, auth_secret);
    }

    pub fn authenticate(
        &self,
        secret: &SecretKey,
        election_id: Uuid,
        ballot_id: Uuid,
        voter_public_key: &PublicKey,
    ) -> Result<Authentication, ()> {
        let package = AuthPackage {
            election_id,
            ballot_id,
            voter_public_key: voter_public_key.clone(),
        };
        let serialized = serde_cbor::to_vec(&package).unwrap();

        let expanded: ExpandedSecretKey = secret.into();
        let signature = expanded.sign(&serialized, &self.public_key);
        let authentication = Authentication {
            authenticator: self.id,
            signature: signature,
        };

        Ok(authentication)
    }

    pub fn verify(
        &self,
        election_id: Uuid,
        ballot_id: Uuid,
        voter_public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let package = AuthPackage {
            election_id,
            ballot_id,
            voter_public_key: voter_public_key.clone(),
        };
        let serialized = serde_cbor::to_vec(&package).unwrap();

        self.public_key.verify_strict(&serialized, signature)
    }
}

// TODO: Be smarter about lifetimes here so we don't need to clone PublicKey
#[derive(Serialize, Deserialize, Clone)]
struct AuthPackage {
    election_id: Uuid,
    ballot_id: Uuid,
    voter_public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {
    pub authenticator: Uuid,
    pub signature: Signature,
}
