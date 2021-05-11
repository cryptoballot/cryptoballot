use crate::*;
use rand::{CryptoRng, Rng};
use cryptid::elgamal::PublicKey as ElGamalPublicKey;
use cryptid::elgamal::{CurveElem};
use cryptid::threshold::{
    Decryption, KeygenCommitment, Threshold, ThresholdGenerator, ThresholdParty,
};
use cryptid::util::AsBase64;
use cryptid::Scalar;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use std::collections::HashMap;
use std::convert::TryInto;
use uuid::Uuid;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use hkdf::Hkdf;
use hex::{FromHex, ToHex};
use core::iter::FromIterator;
use serde::{
    de::Error as SerdeError, de::Unexpected, de::Visitor, Deserialize, Deserializer, Serialize,
    Serializer,
};
use std::convert::TryFrom;


/// A trustee is responsible for safeguarding a secret share (a portion of the secret vote decryption key),
/// distributed by the election authority via Shamir Secret Sharing.
///
/// Most elections will have a handful of trustees (between 3 and 30), with a quorum being set to about 2/3
/// the total number of trustees. Any quorum of trustees may decrypt the votes.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Trustee {
    pub id: uuid::Uuid,
    pub public_key: PublicKey,
    pub ecies_key: ecies_ed25519::PublicKey,
    pub index: usize,

    #[serde(default)]
    #[serde(skip_serializing)]
    pub num_trustees: usize,

    #[serde(default)]
    #[serde(skip_serializing)]
    pub threshold: usize,
}

impl Trustee {
    pub fn from_election_tx(election_tx: &ElectionTransaction, pkey: PublicKey) -> Self {
        let mut trustee = Trustee::default();

        for maybe_trustee in &election_tx.trustees {
            if maybe_trustee.public_key == pkey {
                trustee = maybe_trustee.clone();
            }
        }

        // TODO: Make this a result
        if trustee.index == 0 {
            panic!("No trustee with that public key found in election");
        }

        trustee.num_trustees = election_tx.trustees.len();
        trustee.threshold = election_tx.trustees_threshold as usize;

        trustee
    }

    /// Create a new trustee
    pub fn new(index: usize, num_trustees: usize, threshold: usize) -> (Self, SecretKey) {
        if index == 0 {
            panic!("Trustee index cannot be zero");
        }

        let (secret, public_key) = generate_keypair();

        let (_ecies_secret, ecies_key) = Self::ecies_keys(&secret);
 
        let trustee = Trustee {
            id: Uuid::new_v4(),
            index,
            public_key,
            ecies_key,
            num_trustees, 
            threshold
        };
        (trustee, secret)
    }

    pub fn keygen_commitment(&self, sk: &SecretKey) -> KeygenCommitment {
        self.generator(sk).get_commitment()
    }

    pub fn generate_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        sk: &SecretKey, 
        trustees: &[Trustee],
        commitments: &[(usize, KeygenCommitment)],
    ) -> Vec<(Uuid, EncryptedShare)> {
        let mut theshold_generator =  self.generator(sk);

        for (index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*index, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        let mut shares = Vec::new();
        for trustee in trustees {
            let share = theshold_generator.get_polynomial_share(trustee.index).unwrap();

            // Encrypt the share with the public key such that only the holder of the secret key can decrypt. 
            let encrypted = EncryptedShare(ecies_ed25519::encrypt(&trustee.ecies_key, share.as_bytes(), rng).unwrap());

            shares.push((trustee.id, encrypted));
        }

        shares
    }

    pub fn generate_public_key(
        &self,
        sk: &SecretKey, 
        trustees: &[Trustee],
        commitments: &[(usize, KeygenCommitment)],
        shares: &[(Uuid, EncryptedShare)], // From, Share
    ) -> ElGamalPublicKey {

        // Grab our ecies private key for decryption
        let (ecies_secret_key, _public_key) = Self::ecies_keys(sk);        

        // Decrypt the shares
        let mut decrypted_shared = Vec::<(usize, Scalar)>::with_capacity(shares.len());
        for (sender_uuid, share) in shares {
            match trustees.iter().position(|t| t.id == *sender_uuid) {
                Some(i) => {
                    // TODO: Remove these unwraps on the next two lines
                    let decrypted = ecies_ed25519::decrypt(&ecies_secret_key, share.as_bytes()).unwrap();
                    decrypted_shared.push((trustees[i].index, Scalar::try_from(decrypted).unwrap()));
                },
                None => {
                    // TODO: Result
                    panic!("Invalid sender UUID");
                }
            }
        }

        let party = self.generate_party(sk, commitments, &decrypted_shared);
        party.pubkey()
    }

    pub fn ecies_keys(
        sk: &SecretKey, 
    ) -> (ecies_ed25519::SecretKey, ecies_ed25519::PublicKey)  {
        // Generate a HKDF to seed a deterministic RNG
        let h = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut seed = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_ecies_key", &mut seed).unwrap();
 
        let mut rng = ChaCha20Rng::from_seed(seed);

        ecies_ed25519::generate_keypair(&mut rng)
    }

    // Generate a cryptid generator derived from the secret-key
    fn generator(&self, sk: &SecretKey) -> ThresholdGenerator {
        // Generate a HKDF
        // TODO: Should we use the public key as the salt?
        let h = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut seed = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_generator", &mut seed).unwrap();
 
        let mut rng = ChaCha20Rng::from_seed(seed);

        ThresholdGenerator::new(&mut rng, self.index, self.threshold, self.num_trustees)
    }

    fn generate_party(
        &self,
        sk: &SecretKey, 
        commitments: &[(usize, KeygenCommitment)],
        shares: &[(usize, Scalar)], // From, Share
    ) -> ThresholdParty {
        let mut theshold_generator = self.generator(sk);

        for (index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*index, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        for (index, share) in shares {
            theshold_generator
                .receive_share(*index, &share)
                .expect("Invalid share") // TODO Result
        }
 
        theshold_generator.finish().unwrap()
    }

}
pub struct EncryptedShare(Vec<u8>);

impl EncryptedShare {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl ToHex for EncryptedShare {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    } 

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for EncryptedShare {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, hex::FromHexError> {
        let bytes = Vec::<u8>::from_hex(hex)?;
        let es = Self(bytes);
        Ok(es)
    }
}

impl Serialize for EncryptedShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let encoded: Vec<char> = self.encode_hex();
            let encoded: String = encoded.into_iter().collect();
            let result = serializer.serialize_str(&encoded);

            result
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'d> Deserialize<'d> for EncryptedShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct EncryptedShareVisitor;

        impl<'d> Visitor<'d> for EncryptedShareVisitor {
            type Value = EncryptedShare;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An ecies-ed25519 secret key as 32 bytes.")
            }

            fn visit_str<E>(self, input: &str) -> Result<EncryptedShare, E>
            where
                E: SerdeError,
            {
                let bytes = hex::decode(input).or(Err(SerdeError::invalid_value(
                    Unexpected::Other("invalid hex"),
                    &self,
                )))?;
                let es = EncryptedShare(bytes);
                Ok(es)
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<EncryptedShare, E>
            where
                E: SerdeError,
            {
                Ok(EncryptedShare(bytes.to_vec()))
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(EncryptedShareVisitor)
        } else {
            deserializer.deserialize_bytes(EncryptedShareVisitor)
        }
    }
}


#[test]
fn trustee_keygen_test() {
    let mut rng = rand::thread_rng();

    let (trustee_1, skey_1) = Trustee::new(1, 3, 2);
    let (trustee_2, skey_2) = Trustee::new(2, 3, 2);
    let (trustee_3, skey_3) = Trustee::new(3, 3, 2);

    let trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];

    let commit_1 = trustee_1.keygen_commitment(&skey_1);
    let commit_2 = trustee_2.keygen_commitment(&skey_2);
    let commit_3 = trustee_3.keygen_commitment(&skey_3);

    let commitments = [
        (1, commit_1),
        (2, commit_2),
        (3, commit_3),
    ];

    // Map of: recipient -> (sender, share)
    let mut shares = HashMap::<Uuid, Vec<(Uuid, EncryptedShare)>>::new();
    for (to, share) in trustee_1.generate_shares(&mut rng, &skey_1, &trustees, &commitments) {
        shares.entry(to).or_insert(Vec::new()).push((trustee_1.id, share));
    }
    for (to, share) in trustee_2.generate_shares(&mut rng, &skey_2, &trustees, &commitments) {
        shares.entry(to).or_insert(Vec::new()).push((trustee_2.id, share));
    }
    for (to, share) in trustee_3.generate_shares(&mut rng, &skey_3, &trustees, &commitments) {
        shares.entry(to).or_insert(Vec::new()).push((trustee_3.id, share));
    }

    let trustee_1_pubkey = trustee_1.generate_public_key(&skey_1, &trustees, &commitments, &shares[&trustee_1.id]);
    let trustee_2_pubkey = trustee_2.generate_public_key(&skey_2, &trustees, &commitments, &shares[&trustee_2.id]);
    let trustee_3_pubkey = trustee_3.generate_public_key(&skey_3, &trustees, &commitments, &shares[&trustee_3.id]);

    assert_eq!(trustee_1_pubkey, trustee_2_pubkey);
    assert_eq!(trustee_1_pubkey, trustee_3_pubkey);
    assert_eq!(trustee_2_pubkey, trustee_3_pubkey);
}

