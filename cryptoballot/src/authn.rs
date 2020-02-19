use crate::*;
use ed25519_dalek::PublicKey;
use rsa::{RSAPrivateKey, RSAPublicKey};
use rsa_fdh::blind;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthPublicKey(#[serde(with = "RSAPublicKeyHex")] RSAPublicKey);

impl AsRef<RSAPublicKey> for AuthPublicKey {
    fn as_ref(&self) -> &RSAPublicKey {
        &self.0
    }
}

/// An Authenticator is responsible for authenticating a voter as allowed to vote a specific ballot in an election.
///
/// An authenticator receives the following from a voter:
///   1. Voter's bonefides (government-id, security-code, password etc).
///   2. Election ID and Ballot ID
///   3. blinded auth-package triplet of (`election-id`, `ballot-id`, `voter-public-key`)
///
/// The authenticator first checks the election-id and ballot-id against the voter's bonefides
/// (this is implementation specific and out of scope of CryptoBallot). After satisfied that the voter
/// is allowed to vote this election and ballot, the authenticator blind-signs the blinded triplet and
/// returns the signature to the voter who will unblind it.
///
/// Before the election, the authenticator will generate a signing keypair for each ballot-id. Having
/// on key per ballot ensures that the blinded triplet matches the correct election and ballot.
///
/// WARNING: The secret keys used to sign blinded triplets must NOT be used for any other purpose.
/// Doing so can result in secret key disclosure.
#[derive(Serialize, Deserialize, Clone)]
pub struct Authenticator {
    pub id: uuid::Uuid,

    pub public_keys: BTreeMap<Uuid, AuthPublicKey>,
}

impl Authenticator {
    /// Create a new Authenticator, generating keys for provided ballot-ids.
    ///
    /// For good security, keysize should be at least 2048 bits, and ideally 4096 bits.
    ///
    /// WARNING: The secret keys generated here must NOT be used for any other purpose.
    /// Doing so can result in secret key disclosure.
    pub fn new(
        keysize: usize,
        ballot_ids: &[Uuid],
    ) -> Result<(Self, HashMap<Uuid, RSAPrivateKey>), Error> {
        // If we are in release mode, make sure we are at least 2048 bits
        #[cfg(not(debug_assertions))]
        assert!(
            keysize >= 2048,
            "keysize must be at least 2048 bits in release mode"
        );

        // Create the keys
        let mut rng = rand::rngs::OsRng {};
        let mut public_keys = BTreeMap::<Uuid, AuthPublicKey>::new();
        let mut secret_keys = HashMap::<Uuid, RSAPrivateKey>::with_capacity(ballot_ids.len());

        for ballot_id in ballot_ids {
            let secret = RSAPrivateKey::new(&mut rng, keysize)?;
            let public: RSAPublicKey = secret.clone().into();

            public_keys.insert(*ballot_id, AuthPublicKey(public));
            secret_keys.insert(*ballot_id, secret);
        }

        let authenticator = Authenticator {
            id: Uuid::new_v4(),
            public_keys: public_keys,
        };

        Ok((authenticator, secret_keys))
    }

    /// Sign the blinded (`election-id`, `ballot-id`, `voter-public-key`) auth-package triplet.
    ///
    /// This should only be called after verifying the voter's bonefides (eg government-id, security-code, password etc)
    /// and that they are authorized to vote the requested election and ballot.
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

    /// Verify the authenticator signature
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
        let public_key = self
            .public_keys
            .get(&ballot_id)
            .ok_or(ValidationError::BallotDoesNotExist)?;

        let digest = package.digest(&public_key.0);

        // Verify the signature
        blind::verify(&public_key.0, &digest, &signature)
            .map_err(|_| ValidationError::AuthSignatureVerificationFailed)
    }
}

/// The Auth Package triplet of election-id, ballot-id, and voter public key
///
/// Make sure this package is blinded before being sent to the authenticator to keep the voter's
/// public-key secret from the authenticator.
// TODO: Be smarter about lifetimes here so we don't need to clone PublicKey
#[derive(Serialize, Deserialize, Clone)]
pub struct AuthPackage {
    election_id: Identifier,
    ballot_id: Uuid,
    voter_public_key: PublicKey,
}

impl AuthPackage {
    /// Create a new authentication package
    pub fn new(election_id: Identifier, ballot_id: Uuid, voter_public_key: PublicKey) -> Self {
        AuthPackage {
            election_id,
            ballot_id,
            voter_public_key,
        }
    }

    /// Blind the authentication package, readiying it to be send to the authenticator
    pub fn blind(&self, signer_pub_key: &RSAPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut csprng = rand::rngs::OsRng {};

        let digest = self.digest(signer_pub_key);

        // Get the blinded digest and the secret unblinder
        let (blinded_digest, unblinder) = blind::blind(&mut csprng, signer_pub_key, &digest);

        (blinded_digest, unblinder)
    }

    fn pack(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("cryptoballot: error packing auth package")
    }

    fn digest(&self, signer_pub_key: &RSAPublicKey) -> Vec<u8> {
        let packed = self.pack();

        // Hash the contents of the message with a Full Domain Hash, getting the digest
        let digest = blind::hash_message::<Sha256, _>(&signer_pub_key, &packed)
            .expect("Error getting auth package digest");

        digest
    }
}

/// An Authentication is returned by an authenticator, clearing the voter to vote.
///
/// The sigature returned by the authenticator is blind, and must be unblinded by the voter before use.
#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {
    pub authenticator: Uuid,

    #[serde(with = "hex_serde")]
    pub signature: Vec<u8>,
}

impl Authentication {
    /// Unblind the signature, reading it for use in a Vote transaction.
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
        let (authenticator, auth_secrets) = Authenticator::new(256, &vec![ballot_id]).unwrap();

        // Create the auth package
        let auth_package = AuthPackage::new(election_id, ballot_id, voter_public);

        // Blind the auth package
        let public_key = authenticator.public_keys.get(&ballot_id).unwrap().as_ref();
        let (blinded, unblinder) = auth_package.blind(&public_key);

        // Get it signed by the authenticator and unblind it
        let auth_secret = auth_secrets.get(&ballot_id).unwrap();
        let auth = authenticator.authenticate(&auth_secret, &blinded);
        let auth = auth.unblind(public_key, unblinder);

        // Check that it's still valid even after unblinding
        authenticator
            .verify(election_id, ballot_id, &voter_public, &auth.signature)
            .unwrap();
    }
}
