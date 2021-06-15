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
use x25519_dalek as x25519;

const ENCRYPT_NONCE_SIZE: usize = 12;

/// A trustee is responsible for safeguarding a secret share (a portion of the secret vote decryption key),
/// distributed by the election authority via Shamir Secret Sharing.
///
/// Most elections will have a handful of trustees (between 3 and 30), with a quorum being set to about 2/3
/// the total number of trustees. Any quorum of trustees may decrypt the votes.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Trustee {
    #[serde(with = "EdPublicKeyHex")]
    pub public_key: PublicKey,
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

        let trustee = Trustee {
            index: index,
            public_key,
            num_trustees,
            threshold,
        };
        (trustee, secret)
    }

    pub fn keygen_commitment(&self, sk: &SecretKey, election_id: Identifier) -> KeygenCommitment {
        self.generator(sk, election_id).get_commitment()
    }

    pub fn generate_shares<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        sk: &SecretKey,
        x25519_public_keys: &[(u8, x25519::PublicKey)],
        election_id: Identifier,
        commitments: &[(u8, KeygenCommitment)],
    ) -> IndexMap<u8, EncryptedShare> {
        let mut theshold_generator = self.generator(sk, election_id);

        for (trustee_index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*trustee_index as usize, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        let mut shares = IndexMap::with_capacity(commitments.len());
        for (index, public_key) in x25519_public_keys {
            let share = theshold_generator
                .get_polynomial_share(*index as usize)
                .unwrap();

            let shared_secret = self.shared_secret(sk, election_id, public_key);

            // Encrypt the share with the public key such that only the holder of the secret key can decrypt.
            let encrypted = EncryptedShare::new(rng, shared_secret, &share);

            shares.insert(*index, encrypted);
        }

        shares
    }

    fn decrypt_shares(
        &self,
        sk: &SecretKey,
        shares: &[(u8, EncryptedShare)],
        x25519_public_keys: &[(u8, x25519::PublicKey)],
        election_id: Identifier,
    ) -> Result<Vec<(u8, Scalar)>, ValidationError> {
        let mut decrypted_shared = Vec::<(u8, Scalar)>::with_capacity(shares.len());
        for (sender_index, share) in shares {
            let mut public_key = None;
            for (index, x25519_public_key) in x25519_public_keys {
                if index == sender_index {
                    public_key = Some(x25519_public_key);
                }
            }
            let public_key = public_key.ok_or(ValidationError::TrusteeMissing(*sender_index))?;

            let shared_secret = self.shared_secret(sk, election_id, public_key);
            let decrypted = share.decrypt(shared_secret)?;

            decrypted_shared.push((*sender_index, decrypted));
        }

        Ok(decrypted_shared)
    }

    fn x25519_secret_key(&self, sk: &SecretKey, election_id: Identifier) -> x25519::StaticSecret {
        // Generate a HKDF, using the election-id as the salt
        let h = Hkdf::<Sha256>::new(Some(&election_id.to_bytes()), sk.as_bytes());
        let mut secret = [0u8; 32];
        h.expand(b"cryptoballot_trustee_x25519_secret_key", &mut secret)
            .unwrap();

        x25519::StaticSecret::from(secret)
    }

    pub fn x25519_public_key(&self, sk: &SecretKey, election_id: Identifier) -> x25519::PublicKey {
        let secret = self.x25519_secret_key(sk, election_id);

        x25519::PublicKey::from(&secret)
    }

    fn shared_secret(
        &self,
        sk: &SecretKey,
        election_id: Identifier,
        sender: &x25519::PublicKey,
    ) -> [u8; 32] {
        let x25519_secret_key = self.x25519_secret_key(sk, election_id);
        let shared_secret = x25519_secret_key.diffie_hellman(sender);

        // Generate a HKDF, using the election-id as the salt
        let h = Hkdf::<Sha256>::new(Some(&election_id.to_bytes()), shared_secret.as_bytes());
        let mut shared_bytes = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_shared_secret", &mut shared_bytes)
            .unwrap();

        shared_bytes
    }

    pub fn generate_public_key(
        &self,
        sk: &SecretKey,
        x25519_public_keys: &[(u8, x25519::PublicKey)],
        commitments: &[(u8, KeygenCommitment)],
        shares: &[(u8, EncryptedShare)], // From, Share
        election_id: Identifier,
    ) -> Result<(ElGamalPublicKey, PubkeyProof), ValidationError> {
        let decryped_shares = self.decrypt_shares(sk, shares, x25519_public_keys, election_id)?;
        let party = self.generate_party(sk, &commitments, &decryped_shares, election_id);
        Ok((party.pubkey(), party.pubkey_proof()))
    }

    pub fn partial_decrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        sk: &SecretKey,
        x25519_public_keys: &[(u8, x25519::PublicKey)],
        commitments: &[(u8, KeygenCommitment)],
        shares: &[(u8, EncryptedShare)],
        encrypted_vote: &Ciphertext,
        election_id: Identifier,
    ) -> Result<DecryptShare, ValidationError> {
        let decryped_shares = self.decrypt_shares(sk, shares, x25519_public_keys, election_id)?;
        let party = self.generate_party(sk, &commitments, &decryped_shares, election_id);

        Ok(party.decrypt_share(encrypted_vote, rng))
    }

    // Generate a cryptid generator derived from the secret-key
    fn generator(&self, sk: &SecretKey, election_id: Identifier) -> ThresholdGenerator {
        // Generate a HKDF, using the election-id as the salt
        let h = Hkdf::<Sha256>::new(Some(&election_id.to_bytes()), sk.as_bytes());
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
        election_id: Identifier,
    ) -> ThresholdParty {
        let mut theshold_generator = self.generator(sk, election_id);

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
    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        shared_secret: [u8; 32],
        share: &Scalar,
    ) -> EncryptedShare {
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

        let key = Key::from_slice(&shared_secret);
        let cipher = Aes256Gcm::new(key);

        let nonce = rng.gen::<[u8; ENCRYPT_NONCE_SIZE]>();
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce, &share.as_bytes()[..]).unwrap();

        let mut encrypted = Vec::with_capacity(ciphertext.len() + ENCRYPT_NONCE_SIZE);
        encrypted.extend_from_slice(nonce);
        encrypted.extend_from_slice(&ciphertext);

        EncryptedShare(encrypted)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn decrypt(&self, shared_secret: [u8; 32]) -> Result<Scalar, ValidationError> {
        use aes_gcm::aead::{Aead, NewAead};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let key = Key::from(shared_secret);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&self.0[..ENCRYPT_NONCE_SIZE]);

        let plaintext = cipher
            .decrypt(nonce, &self.0[ENCRYPT_NONCE_SIZE..])
            .map_err(|_| ValidationError::ShareDecryptionError)?;

        let share =
            Scalar::try_from(plaintext).map_err(|_| ValidationError::ShareDecryptionError)?;

        Ok(share)
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
    let election_id = ElectionTransaction::build_id(rng.gen());

    let (trustee_1, skey_1) = Trustee::new(1, 3, 2);
    let (trustee_2, skey_2) = Trustee::new(2, 3, 2);
    let (trustee_3, skey_3) = Trustee::new(3, 3, 2);

    let commit_1 = trustee_1.keygen_commitment(&skey_1, election_id);
    let commit_2 = trustee_2.keygen_commitment(&skey_2, election_id);
    let commit_3 = trustee_3.keygen_commitment(&skey_3, election_id);

    let commitments = [
        (trustee_1.index, commit_1),
        (trustee_2.index, commit_2),
        (trustee_3.index, commit_3),
    ];

    let x25519_public_1 = trustee_1.x25519_public_key(&skey_1, election_id);
    let x25519_public_2 = trustee_2.x25519_public_key(&skey_2, election_id);
    let x25519_public_3 = trustee_3.x25519_public_key(&skey_3, election_id);

    let x25519_public_keys = [
        (trustee_1.index, x25519_public_1),
        (trustee_2.index, x25519_public_2),
        (trustee_3.index, x25519_public_3),
    ];

    // Map of: recipient -> (sender, share)
    let mut shares = IndexMap::<u8, Vec<(u8, EncryptedShare)>>::new();
    for (to, share) in trustee_1.generate_shares(
        &mut rng,
        &skey_1,
        &x25519_public_keys,
        election_id,
        &commitments,
    ) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_1.index, share));
    }
    for (to, share) in trustee_2.generate_shares(
        &mut rng,
        &skey_2,
        &x25519_public_keys,
        election_id,
        &commitments,
    ) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_2.index, share));
    }
    for (to, share) in trustee_3.generate_shares(
        &mut rng,
        &skey_3,
        &x25519_public_keys,
        election_id,
        &commitments,
    ) {
        shares
            .entry(to)
            .or_insert(Vec::new())
            .push((trustee_3.index, share));
    }

    let (trustee_1_pubkey, trustee_1_pk_proof) = trustee_1
        .generate_public_key(
            &skey_1,
            &x25519_public_keys,
            &commitments,
            &shares[&trustee_1.index],
            election_id,
        )
        .unwrap();
    let (trustee_2_pubkey, trustee_2_pk_proof) = trustee_2
        .generate_public_key(
            &skey_2,
            &x25519_public_keys,
            &commitments,
            &shares[&trustee_2.index],
            election_id,
        )
        .unwrap();
    let (trustee_3_pubkey, _trustee_3_pk_proof) = trustee_3
        .generate_public_key(
            &skey_3,
            &x25519_public_keys,
            &commitments,
            &shares[&trustee_3.index],
            election_id,
        )
        .unwrap();

    assert_eq!(trustee_1_pubkey, trustee_2_pubkey);
    assert_eq!(trustee_1_pubkey, trustee_3_pubkey);
    assert_eq!(trustee_2_pubkey, trustee_3_pubkey);

    let vote = "SANTA CLAUS";
    let ciphertext = trustee_1_pubkey.encrypt(&mut rng, vote.as_bytes());

    let partial_decrypt_1 = trustee_1
        .partial_decrypt(
            &mut rng,
            &skey_1,
            &x25519_public_keys,
            &commitments,
            &shares[&trustee_1.index],
            &ciphertext,
            election_id,
        )
        .unwrap();

    let partial_decrypt_2 = trustee_2
        .partial_decrypt(
            &mut rng,
            &skey_2,
            &x25519_public_keys,
            &commitments,
            &shares[&trustee_2.index],
            &ciphertext,
            election_id,
        )
        .unwrap();

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
