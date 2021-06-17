// We define in our crate:
use crate::Error;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;
use rsa::RSAPublicKey;
use std::borrow::Cow;
use std::convert::TryFrom;
use x25519_dalek as x25519;

pub use hex_buffer_serde::Hex;
// a single-purpose type for use in `#[serde(with)]`
pub enum EdPublicKeyHex {}

impl Hex<PublicKey> for EdPublicKeyHex {
    type Error = Error;

    fn create_bytes(public_key: &PublicKey) -> Cow<[u8]> {
        public_key.as_ref().into()
    }

    fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(bytes)?)
    }
}

pub enum X25519PublicKeyHex {}

impl Hex<x25519::PublicKey> for X25519PublicKeyHex {
    type Error = Error;

    fn create_bytes(public_key: &x25519::PublicKey) -> Cow<[u8]> {
        let bytes = public_key.to_bytes().to_vec();
        Cow::from(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<x25519::PublicKey, Error> {
        if bytes.len() != 32 {
            return Err(Error::InvalidX25519PublicKey);
        }

        let mut key_bytes: [u8; 32] = [0; 32];
        key_bytes.copy_from_slice(bytes);

        Ok(x25519::PublicKey::from(key_bytes))
    }
}

// a single-purpose type for use in `#[serde(with)]`
pub enum EdSignatureHex {}

impl Hex<Signature> for EdSignatureHex {
    type Error = Error;

    fn create_bytes(sig: &Signature) -> Cow<[u8]> {
        let bytes = sig.to_bytes().to_vec();
        Cow::from(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::try_from(bytes)?)
    }
}

// a single-purpose type for use in `#[serde(with)]`
pub enum RSAPublicKeyHex {}

impl Hex<RSAPublicKey> for RSAPublicKeyHex {
    type Error = Error;

    fn create_bytes(public_key: &RSAPublicKey) -> Cow<[u8]> {
        serde_cbor::to_vec(public_key).unwrap().into()
    }

    fn from_bytes(bytes: &[u8]) -> Result<RSAPublicKey, Error> {
        Ok(serde_cbor::from_slice(bytes)?)
    }
}
