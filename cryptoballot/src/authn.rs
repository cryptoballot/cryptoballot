use crate::*;
use ed25519_dalek::PublicKey;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rsa_fdh::blind;
use sha2::Sha256;
use uuid::Uuid;
#[derive(Serialize, Deserialize, Clone)]
pub struct Authenticator {
    pub id: uuid::Uuid,
    pub public_key: RSAPublicKey,
    // TODO: Enum of type of auth provided.
    // pub auth_type: AuthType,
}

impl Authenticator {
    pub fn new(keysize: usize) -> Result<(Self, RSAPrivateKey), Error> {
        // Create the keys
        let mut rng = rand::rngs::OsRng {};
        let secret = RSAPrivateKey::new(&mut rng, keysize)?;
        let public: RSAPublicKey = secret.clone().into();
        let authenticator = Authenticator {
            id: Uuid::new_v4(),
            public_key: public,
        };

        Ok((authenticator, secret))
    }

    pub fn authenticate(
        &self,
        secret: &RSAPrivateKey,
        blinded_auth_package: &[u8],
    ) -> Authentication {
        let mut rng = rand::rngs::OsRng {};
        let blind_signature = blind::sign(&mut rng, &secret, blinded_auth_package).unwrap();

        let authentication = Authentication {
            authenticator: self.id,
            signature: blind_signature,
        };

        authentication
    }

    pub fn verify(
        &self,
        election_id: Identifier,
        ballot_id: Uuid,
        voter_public_key: &PublicKey,
        signature: &[u8],
    ) -> Result<(), ValidationError> {
        let package = AuthPackage {
            election_id,
            ballot_id,
            voter_public_key: voter_public_key.clone(),
        };
        let digest = package.digest(&self.public_key);

        // Verify the signature
        blind::verify(&self.public_key, &digest, &signature)
            .map_err(|_| ValidationError::AuthSignatureVerificationFailed)
    }
}

// TODO: Be smarter about lifetimes here so we don't need to clone PublicKey
#[derive(Serialize, Deserialize, Clone)]
pub struct AuthPackage {
    election_id: Identifier,
    ballot_id: Uuid,
    voter_public_key: PublicKey,
}

impl AuthPackage {
    pub fn new(election_id: Identifier, ballot_id: Uuid, voter_public_key: PublicKey) -> Self {
        AuthPackage {
            election_id,
            ballot_id,
            voter_public_key,
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("cryptoballot: error packing auth package")
    }

    pub fn digest(&self, signer_pub_key: &RSAPublicKey) -> Vec<u8> {
        let packed = self.pack();

        // Hash the contents of the message with a Full Domain Hash, getting the digest
        let digest = blind::hash_message::<Sha256, _>(&signer_pub_key, &packed)
            .expect("Error getting auth package digest");

        digest
    }

    pub fn blind(&self, signer_pub_key: &RSAPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut csprng = rand::rngs::OsRng {};

        let digest = self.digest(signer_pub_key);

        // Get the blinded digest and the secret unblinder
        let (blinded_digest, unblinder) = blind::blind(&mut csprng, signer_pub_key, &digest);

        (blinded_digest, unblinder)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {
    pub authenticator: Uuid,
    pub signature: Vec<u8>,
}

impl Authentication {
    pub fn unblind(self, signer_pub_key: &RSAPublicKey, unblinder: Vec<u8>) -> Self {
        // Unblind the signature
        let unblinded = blind::unblind(signer_pub_key, &self.signature, &unblinder);
        Authentication {
            authenticator: self.authenticator,
            signature: unblinded,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::*;
    use uuid::Uuid;

    #[test]
    fn test_blind_signing() {
        let election_id = Identifier::new_for_election();
        let ballot_id = Uuid::new_v4();
        let (_voter_secret, voter_public) = generate_keypair();

        // Create authenticator - using insecure 256 bit key for testing purposes
        let (authenticator, auth_secret) = Authenticator::new(256).unwrap();

        // Create the auth package
        let auth_package = AuthPackage::new(election_id, ballot_id, voter_public);

        // Blind the auth package
        let (blinded, unblinder) = auth_package.blind(&authenticator.public_key);

        // Get it signed by the authenticator and unblind it
        let auth = authenticator.authenticate(&auth_secret, &blinded);
        let auth = auth.unblind(&authenticator.public_key, unblinder);

        // Check that it's still valid even after unblinding
        authenticator
            .verify(election_id, ballot_id, &voter_public, &auth.signature)
            .unwrap();
    }
}
