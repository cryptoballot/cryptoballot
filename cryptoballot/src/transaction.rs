use crate::*;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use num_enum::TryFromPrimitive;
use rand::Rng;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::AsRef;
use std::convert::From;
use std::convert::TryInto;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Transaction {
    Election(Signed<ElectionTransaction>),
    Vote(Signed<VoteTransaction>),
    SecretShare(Signed<SecretShareTransaction>),
    Decryption(Signed<DecryptionTransaction>),
}

impl Transaction {
    pub fn transaction_type(&self) -> TransactionType {
        // TODO: use a macro
        match self {
            Transaction::Election(_) => TransactionType::Election,
            Transaction::Vote(_) => TransactionType::Vote,
            Transaction::SecretShare(_) => TransactionType::SecretShare,
            Transaction::Decryption(_) => TransactionType::Decryption,
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("cryptoballot: Unexpected error packing transaction")
    }

    pub fn unpack(packed: &[u8]) -> Result<Self, Error> {
        Ok(serde_cbor::from_slice(packed)?)
    }

    // TODO: use a macro
    pub fn id(&self) -> Identifier {
        match self {
            Transaction::Election(signed) => signed.tx.id,
            Transaction::Vote(signed) => signed.tx.id,
            Transaction::SecretShare(signed) => signed.tx.id,
            Transaction::Decryption(signed) => signed.tx.id,
        }
    }
}

// TODO: use a macro
impl From<Transaction> for Signed<ElectionTransaction> {
    fn from(tx: Transaction) -> Self {
        match tx {
            Transaction::Election(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

// TODO: use a macro
impl From<Transaction> for Signed<VoteTransaction> {
    fn from(tx: Transaction) -> Self {
        match tx {
            Transaction::Vote(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

// TODO: use a macro
impl From<Transaction> for Signed<DecryptionTransaction> {
    fn from(tx: Transaction) -> Self {
        match tx {
            Transaction::Decryption(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

// TODO: use a macro
impl From<Transaction> for Signed<SecretShareTransaction> {
    fn from(tx: Transaction) -> Self {
        match tx {
            Transaction::SecretShare(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

pub trait Signable: Serialize {
    fn id(&self) -> Identifier;
    fn public(&self) -> Option<PublicKey>;

    fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("cryptoballot: Unexpected error serializing transaction")
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Signed<T: Signable> {
    pub tx: T,
    pub sig: Signature,
}

impl<T: Signable + Serialize> Signed<T> {
    pub fn sign(secret: &SecretKey, transaction: T) -> Result<Self, Error> {
        let public_key = PublicKey::from(secret);
        if let Some(tx_public) = transaction.public() {
            if public_key != tx_public {
                return Err(Error::MismatchedPublicKeys);
            }
        }

        let serialized = transaction.as_bytes();

        let expanded: ExpandedSecretKey = secret.into();
        let signature = expanded.sign(&serialized, &public_key);

        Ok(Signed {
            tx: transaction,
            sig: signature,
        })
    }

    pub fn verify_signature(&self) -> Result<(), ValidationError> {
        let serialized = self.tx.as_bytes();

        if let Some(tx_public) = self.tx.public() {
            Ok(tx_public.verify(&serialized, &self.sig)?)
        } else {
            Ok(())
        }
    }

    pub fn inner(&self) -> &T {
        &self.tx
    }

    pub fn id(&self) -> Identifier {
        self.tx.id()
    }
}

impl<T: Signable + Serialize> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {
        &self.tx
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Identifier {
    pub election_id: [u8; 15],
    pub transaction_type: TransactionType,
    pub unique_id: [u8; 16],
}

impl Identifier {
    pub fn new(election_id: Identifier, transaction_type: TransactionType) -> Self {
        let mut csprng = rand::rngs::OsRng {};

        let election_id = election_id.election_id;
        let unique_id: [u8; 16] = csprng.gen();
        Identifier {
            election_id,
            transaction_type,
            unique_id,
        }
    }

    pub fn new_for_election() -> Self {
        let mut csprng = rand::rngs::OsRng {};

        let election_id: [u8; 15] = csprng.gen();
        let transaction_type = TransactionType::Election;
        let unique_id: [u8; 16] = csprng.gen();
        Identifier {
            election_id,
            transaction_type,
            unique_id,
        }
    }
}

impl ToString for Identifier {
    fn to_string(&self) -> String {
        let election_id = hex::encode(self.election_id);
        let transaction_type = hex::encode([self.transaction_type as u8]);
        let unique_id = hex::encode(self.unique_id);

        format!("{}{}{}", election_id, transaction_type, unique_id)
    }
}

impl FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| Error::IdentifierBadHex)?;

        if bytes.len() != 32 {
            return Err(Error::IdentifierBadLen);
        }

        // These unwraps are OK - we know the length is valid
        let election_id: [u8; 15] = bytes[0..15].try_into().unwrap();
        let transaction_type = TransactionType::try_from_primitive(bytes[15]).unwrap();
        let unique_id: [u8; 16] = bytes[16..].try_into().unwrap();

        Ok(Identifier {
            election_id,
            transaction_type,
            unique_id,
        })
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Serialize, Deserialize, TryFromPrimitive, Copy, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TransactionType {
    Election,
    Vote,
    SecretShare,
    Decryption,
}
