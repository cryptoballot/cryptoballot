//! ECIES-ed25519: An Integrated Encryption Scheme on Twisted Edwards Curve25519.
//!
//! It uses many of the same primitives as the ed25519 signature scheme, but is also different.
//!   - It uses the same Secret Key representation as the ed25519 signature scheme.
//!   - It uses a different Public Key representation. While the ed25519 signature scheme hashes the
//!     secret key and mangles some bits before using it to derive the public key,
//!     ECIES-ed25519 uses the secret key directly. This means you should take care to
//!     use a good secure RNG or KDF to generate a your secret key.

use aes_gcm::aead::{self, generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use ed25519_dalek::{PublicKey, SecretKey};
use hex::FromHex;
use hkdf::Hkdf;
use rand::{thread_rng, Rng};
use sha2::Sha256;

const AES_IV_LENGTH: usize = 12;

type AesKey = [u8; 32];
type SharedSecret = [u8; 32];

/// A ed25519 Public Key meant for use in ECIES
///
/// Neither it's PrivateKey nor should this public key be used for signing
/// or in any other protocol other than ECIES.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EciesPublicKey(PublicKey);

impl EciesPublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// Will return None if the bytes are invalid
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let public = match PublicKey::from_bytes(bytes) {
            Ok(public) => public,
            Err(_) => return None,
        };

        Some(EciesPublicKey(public))
    }

    /// Derive a public key from a private key
    pub fn from_secret(sk: &SecretKey) -> Self {
        let point = &Scalar::from_bits(sk.to_bytes()) * &constants::ED25519_BASEPOINT_TABLE;
        let public = PublicKey::from_bytes(&point.compress().to_bytes()).unwrap();
        EciesPublicKey(public)
    }

    /// Get the Edwards Point for this public key
    pub fn as_point(&self) -> EdwardsPoint {
        CompressedEdwardsY::from_slice(self.0.as_bytes())
            .decompress()
            .unwrap()
    }
}

impl AsRef<[u8]> for EciesPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl FromHex for EciesPublicKey {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = hex::decode(hex)?;
        let pk = EciesPublicKey::from_bytes(&bytes).unwrap(); // TODO unwrap
        Ok(pk)
    }
}

/// Generate a keypair, ready for use in ECIES
pub fn generate_keypair() -> (SecretKey, EciesPublicKey) {
    let mut csprng = rand::rngs::OsRng {};
    let ed25519_dalek::Keypair { public: _, secret } =
        ed25519_dalek::Keypair::generate(&mut csprng);
    let public = EciesPublicKey::from_secret(&secret);
    (secret, public)
}

/// Encrypt a message using ECIES, it can only be decrypted by the receiver's SecretKey.
pub fn encrypt(receiver_pub: &EciesPublicKey, msg: &[u8]) -> Vec<u8> {
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let aes_key = encapsulate(&ephemeral_sk, &receiver_pub);
    let encrypted = aes_encrypt(&aes_key, msg);

    let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
    cipher_text.extend(ephemeral_pk.to_bytes().iter());
    cipher_text.extend(encrypted);

    cipher_text
}

/// Decrypt a ECIES encrypted ciphertext using the receiver's SecretKey.
pub fn decrypt(receiver_sec: &SecretKey, msg: &[u8]) -> Result<Vec<u8>, aead::Error> {
    // TODO: check size of msg and throw error

    let ephemeral_pk = EciesPublicKey::from_bytes(&msg[..PUBLIC_KEY_LENGTH]).unwrap();
    let encrypted = &msg[PUBLIC_KEY_LENGTH..];
    let aes_key = decapsulate(&receiver_sec, &ephemeral_pk);

    aes_decrypt(&aes_key, encrypted)
}

fn hkdf_sha256(master: &[u8]) -> AesKey {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&[], &mut out).unwrap();
    out
}

fn generate_shared(secret: &SecretKey, public: &EciesPublicKey) -> SharedSecret {
    let public = public.as_point();
    let secret = Scalar::from_bits(secret.to_bytes());
    let shared_point = public * secret;
    let shared_point = shared_point.compress();
    shared_point.as_bytes().to_owned()
}

fn encapsulate(emphemeral_sk: &SecretKey, peer_pk: &EciesPublicKey) -> AesKey {
    let shared_point = generate_shared(emphemeral_sk, peer_pk);

    let emphemeral_pk = EciesPublicKey::from_secret(emphemeral_sk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.0.as_bytes().iter());
    master.extend(shared_point.iter());
    hkdf_sha256(master.as_slice())
}

fn decapsulate(sk: &SecretKey, emphemeral_pk: &EciesPublicKey) -> AesKey {
    let shared_point = generate_shared(sk, emphemeral_pk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.0.as_bytes().iter());
    master.extend(shared_point.iter());

    hkdf_sha256(master.as_slice())
}

fn aes_encrypt(key: &AesKey, msg: &[u8]) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let aead = Aes256Gcm::new(key);

    let mut nonce = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);

    let ciphertext = aead
        .encrypt(nonce, msg)
        .expect("cryptoballot: ecies_ed25519: encryption failure!");

    let mut output = Vec::with_capacity(AES_IV_LENGTH + ciphertext.len());
    output.extend(nonce);
    output.extend(ciphertext);

    output
}

fn aes_decrypt(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let key = GenericArray::clone_from_slice(key);
    let aead = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
    let encrypted = &ciphertext[AES_IV_LENGTH..];

    aead.decrypt(nonce, encrypted)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_shared() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair();
        let (peer_sk, peer_pk) = generate_keypair();

        assert_eq!(
            generate_shared(&emphemeral_sk, &peer_pk),
            generate_shared(&peer_sk, &emphemeral_pk)
        );

        // Make sure it fails when wrong keys used
        assert_ne!(
            generate_shared(&emphemeral_sk, &emphemeral_pk),
            generate_shared(&peer_sk, &peer_pk)
        )
    }

    #[test]
    fn test_encapsulation() {
        let (emphemeral_sk, emphemeral_pk) = generate_keypair();
        let (peer_sk, peer_pk) = generate_keypair();

        assert_eq!(
            encapsulate(&emphemeral_sk, &peer_pk),
            decapsulate(&peer_sk, &emphemeral_pk)
        )
    }

    #[test]
    fn test_aes() {
        let mut key = [0u8; 32];
        thread_rng().fill(&mut key);

        let plaintext = b"ABOLISH ICE";
        let encrypted = aes_encrypt(&key, plaintext);
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_ecies_ed25519() {
        let (peer_sk, peer_pk) = generate_keypair();

        let plaintext = b"ABOLISH ICE";

        let encrypted = encrypt(&peer_pk, plaintext);
        let decrypted = decrypt(&peer_sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Test that it fails when using a bad secret key
        let (bad_sk, _) = generate_keypair();
        assert!(decrypt(&bad_sk, &encrypted).is_err());
    }
}
