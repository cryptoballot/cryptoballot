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
use std::ops::Deref;
use std::str::FromStr;

/// An unsigned transaction
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Transaction {
    Election(ElectionTransaction),
    Vote(VoteTransaction),
    SecretShare(SecretShareTransaction),
    Decryption(DecryptionTransaction),
}

impl Transaction {
    /// Get the transaction type
    pub fn transaction_type(&self) -> TransactionType {
        // TODO: use a macro
        match self {
            Transaction::Election(_) => TransactionType::Election,
            Transaction::Vote(_) => TransactionType::Vote,
            Transaction::SecretShare(_) => TransactionType::SecretShare,
            Transaction::Decryption(_) => TransactionType::Decryption,
        }
    }

    /// Get the transaction ID
    // TODO: use a macro
    pub fn id(&self) -> Identifier {
        match self {
            Transaction::Election(tx) => tx.id,
            Transaction::Vote(tx) => tx.id,
            Transaction::SecretShare(tx) => tx.id,
            Transaction::Decryption(tx) => tx.id,
        }
    }
}

/// A signed transaction
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SignedTransaction {
    Election(Signed<ElectionTransaction>),
    Vote(Signed<VoteTransaction>),
    SecretShare(Signed<SecretShareTransaction>),
    Decryption(Signed<DecryptionTransaction>),
}

impl SignedTransaction {
    /// Get the transaction type
    pub fn transaction_type(&self) -> TransactionType {
        // TODO: use a macro
        match self {
            SignedTransaction::Election(_) => TransactionType::Election,
            SignedTransaction::Vote(_) => TransactionType::Vote,
            SignedTransaction::SecretShare(_) => TransactionType::SecretShare,
            SignedTransaction::Decryption(_) => TransactionType::Decryption,
        }
    }

    /// Pack into bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("cryptoballot: Unexpected error packing transaction")
    }

    /// Unpack from bytes
    pub fn from_bytes(packed: &[u8]) -> Result<Self, Error> {
        Ok(serde_cbor::from_slice(packed)?)
    }

    /// Get the transaction ID
    // TODO: use a macro
    pub fn id(&self) -> Identifier {
        match self {
            SignedTransaction::Election(signed) => signed.tx.id,
            SignedTransaction::Vote(signed) => signed.tx.id,
            SignedTransaction::SecretShare(signed) => signed.tx.id,
            SignedTransaction::Decryption(signed) => signed.tx.id,
        }
    }
}

/// This trait should be considered sealed and should not be implemented outside this crate
#[doc(hidden)]
pub trait Signable: Serialize {
    fn id(&self) -> Identifier;
    fn public(&self) -> Option<PublicKey>;
    fn input(&self) -> Vec<Identifier>;

    fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("cryptoballot: Unexpected error serializing transaction")
    }
}

/// A generic signed transaction
#[derive(Serialize, Deserialize, Clone)]
pub struct Signed<T: Signable> {
    pub tx: T,

    #[serde(with = "EdSignatureHex")]
    pub sig: Signature,
}

impl<T: Signable + Serialize> Signed<T> {
    /// Sign a transaction, producing a Signed<T>
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

    /// Verify the signature on a signed transaction
    pub fn verify_signature(&self) -> Result<(), ValidationError> {
        let serialized = self.tx.as_bytes();

        if let Some(tx_public) = self.tx.public() {
            Ok(tx_public.verify(&serialized, &self.sig)?)
        } else {
            Ok(())
        }
    }

    /// Get the inner unsigned transaction
    pub fn inner(&self) -> &T {
        &self.tx
    }

    /// Get the transaction ID
    pub fn id(&self) -> Identifier {
        self.tx.id()
    }
}

impl<T: Signable + Serialize> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {
        &self.tx
    }
}

impl<T: Signable + Serialize> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

/// Transaction identifier
///
/// The identifier defines the election, transction-type, and a unique identifier.
#[derive(Copy, Clone, PartialEq)]
pub struct Identifier {
    pub election_id: [u8; 15],
    pub transaction_type: TransactionType,
    pub unique_id: Option<[u8; 16]>,
}

impl Identifier {
    /// Creat a new Identifier
    pub fn new(election_id: Identifier, transaction_type: TransactionType) -> Self {
        let mut csprng = rand::rngs::OsRng {};

        let election_id = election_id.election_id;
        let unique_id: [u8; 16] = csprng.gen();
        Identifier {
            election_id,
            transaction_type,
            unique_id: Some(unique_id),
        }
    }

    /// Create a new identifier for an election
    pub fn new_for_election() -> Self {
        let mut csprng = rand::rngs::OsRng {};

        let election_id: [u8; 15] = csprng.gen();
        let transaction_type = TransactionType::Election;
        let unique_id: [u8; 16] = [0; 16]; // All zeroes
        Identifier {
            election_id,
            transaction_type,
            unique_id: Some(unique_id),
        }
    }
}

impl ToString for Identifier {
    fn to_string(&self) -> String {
        let election_id = hex::encode(self.election_id);
        let transaction_type = hex::encode([self.transaction_type as u8]);
        let unique_id = match self.unique_id {
            Some(unique_id) => hex::encode(unique_id),
            None => "".to_string(),
        };

        format!("{}{}{}", election_id, transaction_type, unique_id)
    }
}

impl FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| Error::IdentifierBadHex)?;

        if bytes.len() != 32 && bytes.len() != 16 {
            return Err(Error::IdentifierBadLen);
        }
        let has_unique_id = bytes.len() == 32;

        // These unwraps are OK - we know the length is valid
        let election_id: [u8; 15] = bytes[0..15].try_into().unwrap();
        let transaction_type = TransactionType::try_from_primitive(bytes[15]).unwrap();

        let unique_id = if has_unique_id {
            let unique_id: [u8; 16] = bytes[16..].try_into().unwrap();
            Some(unique_id)
        } else {
            None
        };

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

/// A transaction type
#[derive(Serialize, Deserialize, TryFromPrimitive, Copy, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TransactionType {
    Election,
    Vote,
    SecretShare,
    Decryption,
}

// Automatic translation between types
// TODO: Use a macro for all of these
// ----------------------------------

impl From<SignedTransaction> for Signed<ElectionTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Election(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<VoteTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Vote(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<DecryptionTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Decryption(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<SecretShareTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::SecretShare(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<Signed<ElectionTransaction>> for SignedTransaction {
    fn from(tx: Signed<ElectionTransaction>) -> Self {
        SignedTransaction::Election(tx)
    }
}

impl From<Signed<VoteTransaction>> for SignedTransaction {
    fn from(tx: Signed<VoteTransaction>) -> Self {
        SignedTransaction::Vote(tx)
    }
}

impl From<Signed<SecretShareTransaction>> for SignedTransaction {
    fn from(tx: Signed<SecretShareTransaction>) -> Self {
        SignedTransaction::SecretShare(tx)
    }
}

impl From<Signed<DecryptionTransaction>> for SignedTransaction {
    fn from(tx: Signed<DecryptionTransaction>) -> Self {
        SignedTransaction::Decryption(tx)
    }
}

impl AsRef<ElectionTransaction> for SignedTransaction {
    fn as_ref(&self) -> &ElectionTransaction {
        match self {
            SignedTransaction::Election(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<VoteTransaction> for SignedTransaction {
    fn as_ref(&self) -> &VoteTransaction {
        match self {
            SignedTransaction::Vote(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<SecretShareTransaction> for SignedTransaction {
    fn as_ref(&self) -> &SecretShareTransaction {
        match self {
            SignedTransaction::SecretShare(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<DecryptionTransaction> for SignedTransaction {
    fn as_ref(&self) -> &DecryptionTransaction {
        match self {
            SignedTransaction::Decryption(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}
