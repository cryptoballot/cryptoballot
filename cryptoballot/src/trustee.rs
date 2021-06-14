use crate::*;
use core::iter::FromIterator;
use cryptid::elgamal::Ciphertext;
use cryptid::elgamal::PublicKey as ElGamalPublicKey;
use cryptid::threshold::DecryptShare;
use cryptid::threshold::PubkeyProof;
use cryptid::threshold::{KeygenCommitment, Threshold, ThresholdGenerator, ThresholdParty};
use cryptid::Scalar;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use hex::{FromHex, ToHex};
use hkdf::Hkdf;
use indexmap::IndexMap;
use rand::{CryptoRng, Rng};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{
    de::Error as SerdeError, de::Unexpected, de::Visitor, Deserialize, Deserializer, Serialize,
    Serializer,
};
use sha2::Sha256;
use std::convert::TryFrom;

/// A trustee is responsible for safeguarding a secret share (a portion of the secret vote decryption key),
/// distributed by the election authority via Shamir Secret Sharing.
///
/// Most elections will have a handful of trustees (between 3 and 30), with a quorum being set to about 2/3
/// the total number of trustees. Any quorum of trustees may decrypt the votes.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Trustee {
    #[serde(with = "EdPublicKeyHex")]
    pub public_key: PublicKey,
    pub ecies_key: ecies_ed25519::PublicKey,
    pub index: u8,

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
    pub fn new(index: u8, num_trustees: usize, threshold: usize) -> (Self, SecretKey) {
        if index == 0 {
            panic!("Trustee index cannot be zero");
        }

        let (secret, public_key) = generate_keypair();

        let (_ecies_secret, ecies_key) = Self::ecies_keys(&secret);

        let trustee = Trustee {
            index: index,
            public_key,
            ecies_key,
            num_trustees,
            threshold,
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
        commitments: &[(u8, KeygenCommitment)],
    ) -> IndexMap<u8, EncryptedShare> {
        let mut theshold_generator = self.generator(sk);

        for (trustee_index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*trustee_index as usize, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        let mut shares = IndexMap::with_capacity(commitments.len());
        for trustee in trustees {
            let share = theshold_generator
                .get_polynomial_share(trustee.index as usize)
                .unwrap();

            // Encrypt the share with the public key such that only the holder of the secret key can decrypt.
            let encrypted = EncryptedShare(
                ecies_ed25519::encrypt(&trustee.ecies_key, share.as_bytes(), rng).unwrap(),
            );

            shares.insert(trustee.index, encrypted);
        }

        shares
    }

    pub fn generate_public_key(
        &self,
        sk: &SecretKey,
        commitments: &[(u8, KeygenCommitment)],
        shares: &[(u8, EncryptedShare)], // From, Share
    ) -> (ElGamalPublicKey, PubkeyProof) {
        let decryped_shares = self.decrypt_shares(sk, shares);
        let party = self.generate_party(sk, &commitments, &decryped_shares);
        (party.pubkey(), party.pubkey_proof())
    }

    pub fn partial_decrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        sk: &SecretKey,
        commitments: &[(u8, KeygenCommitment)],
        shares: &[(u8, EncryptedShare)],
        encrypted_vote: &Ciphertext,
    ) -> DecryptShare {
        let decryped_shares = self.decrypt_shares(sk, shares);
        let party = self.generate_party(sk, &commitments, &decryped_shares);

        party.decrypt_share(encrypted_vote, rng)
    }

    fn decrypt_shares(&self, sk: &SecretKey, shares: &[(u8, EncryptedShare)]) -> Vec<(u8, Scalar)> {
        // Grab our ecies private key for decryption
        let (ecies_secret_key, _public_key) = Self::ecies_keys(sk);

        let mut decrypted_shared = Vec::<(u8, Scalar)>::with_capacity(shares.len());
        for (sender_index, share) in shares {
            // TODO: Remove these unwraps on the next two lines, use real errors
            let decrypted = ecies_ed25519::decrypt(&ecies_secret_key, share.as_bytes()).unwrap();
            decrypted_shared.push((*sender_index, Scalar::try_from(decrypted).unwrap()));
        }

        decrypted_shared
    }

    pub fn ecies_keys(sk: &SecretKey) -> (ecies_ed25519::SecretKey, ecies_ed25519::PublicKey) {
        // Generate a HKDF to seed a deterministic RNG
        let h = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut seed = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_ecies_key", &mut seed)
            .unwrap();

        let mut rng = ChaCha20Rng::from_seed(seed);

        ecies_ed25519::generate_keypair(&mut rng)
    }

    // Generate a cryptid generator derived from the secret-key
    fn generator(&self, sk: &SecretKey) -> ThresholdGenerator {
        // Generate a HKDF
        // TODO: Should we use the public key as the salt?
        let h = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut seed = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_generator", &mut seed)
            .unwrap();

        let mut rng = ChaCha20Rng::from_seed(seed);

        ThresholdGenerator::new(
            &mut rng,
            self.index as usize,
            self.threshold,
            self.num_trustees,
        )
    }

    fn generate_party(
        &self,
        sk: &SecretKey,
        commitments: &[(u8, KeygenCommitment)],
        shares: &[(u8, Scalar)],
    ) -> ThresholdParty {
        let mut theshold_generator = self.generator(sk);

        for (index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*index as usize, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        for (index, share) in shares {
            theshold_generator
                .receive_share(*index as usize, &share)
                .expect("Invalid share") // TODO Result
        }

        theshold_generator.finish().unwrap()
    }
}

#[derive(Clone, Debug)]
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
fn trustee_e2e_test() {
    use indexmap::IndexMap;

    let mut rng = rand::thread_rng();

    let (trustee_1, skey_1) = Trustee::new(1, 3, 2);
    let (trustee_2, skey_2) = Trustee::new(2, 3, 2);
    let (trustee_3, skey_3) = Trustee::new(3, 3, 2);

    let trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];

    let commit_1 = trustee_1.keygen_commitment(&skey_1);
    let commit_2 = trustee_2.keygen_commitment(&skey_2);
    let commit_3 = trustee_3.keygen_commitment(&skey_3);

    let commitments = [
        (trustee_1.index, commit_1),
        (trustee_2.index, commit_2),
        (trustee_3.index, commit_3),
    ];

    // Map of: recipient -> (sender, share)
    let mut shares = IndexMap::<u8, Vec<(u8, EncryptedShare)>>::new();
    for (to, share) in trustee_1.generate_shares(&mut rng, &skey_1, &trustees, &commitments) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_1.index, share));
    }
    for (to, share) in trustee_2.generate_shares(&mut rng, &skey_2, &trustees, &commitments) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_2.index, share));
    }
    for (to, share) in trustee_3.generate_shares(&mut rng, &skey_3, &trustees, &commitments) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_3.index, share));
    }

    let (trustee_1_pubkey, trustee_1_pk_proof) =
        trustee_1.generate_public_key(&skey_1, &commitments, &shares[&trustee_1.index]);
    let (trustee_2_pubkey, trustee_2_pk_proof) =
        trustee_2.generate_public_key(&skey_2, &commitments, &shares[&trustee_2.index]);
    let (trustee_3_pubkey, _trustee_3_pk_proof) =
        trustee_3.generate_public_key(&skey_3, &commitments, &shares[&trustee_3.index]);

    assert_eq!(trustee_1_pubkey, trustee_2_pubkey);
    assert_eq!(trustee_1_pubkey, trustee_3_pubkey);
    assert_eq!(trustee_2_pubkey, trustee_3_pubkey);

    let vote = "SANTA CLAUS";
    let ciphertext = trustee_1_pubkey.encrypt(&mut rng, vote.as_bytes());

    let partial_decrypt_1 = trustee_1.partial_decrypt(
        &mut rng,
        &skey_1,
        &commitments,
        &shares[&trustee_1.index],
        &ciphertext,
    );

    let partial_decrypt_2 = trustee_2.partial_decrypt(
        &mut rng,
        &skey_2,
        &commitments,
        &shares[&trustee_2.index],
        &ciphertext,
    );

    // Check ZKP of correct partial decryption
    assert!(partial_decrypt_1.verify(&trustee_1_pk_proof, &ciphertext));
    assert!(partial_decrypt_2.verify(&trustee_2_pk_proof, &ciphertext));

    // TODO: Full decryption
    let mut decrypt = cryptid::threshold::Decryption::new(2, &ciphertext);
    decrypt.add_share(
        trustee_1.index as usize,
        &trustee_1_pk_proof,
        &partial_decrypt_1,
    );
    decrypt.add_share(
        trustee_2.index as usize,
        &trustee_2_pk_proof,
        &partial_decrypt_2,
    );

    let decrypted = decrypt.finish().unwrap();

    assert_eq!(vote.as_bytes(), &decrypted);
}
