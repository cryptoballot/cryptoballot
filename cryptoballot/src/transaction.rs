use crate::*;
use content_inspector::ContentType;
use digest::Digest;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use num_enum::TryFromPrimitive;
use rand::Rng;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::convert::AsRef;
use std::convert::From;
use std::convert::TryInto;
use std::ops::Deref;
use std::str::FromStr;

/// An unsigned transaction
/// TODO: Implment From going for specific tx to this emum and vice versa
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match content_inspector::inspect(&bytes) {
            ContentType::UTF_8 => Ok(serde_json::from_slice(&bytes)?),
            ContentType::BINARY => Ok(serde_cbor::from_slice(&bytes)?),
            _ => Err(Error::DeserializationUnknownFormat),
        }
    }

    pub fn validate_tx<S: Store>(&self, s: &S) -> Result<(), ValidationError> {
        match self {
            Transaction::Election(tx) => tx.validate_tx(s),
            Transaction::Vote(tx) => tx.validate_tx(s),
            Transaction::SecretShare(tx) => tx.validate_tx(s),
            Transaction::Decryption(tx) => tx.validate_tx(s),
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // If it starts with `{` then it's JSON
        if bytes[0] == 123 {
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            Ok(serde_cbor::from_slice(&bytes)?)
        }
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

    /// Get the transaction ID
    // TODO: use a macro
    pub fn inputs(&self) -> Vec<Identifier> {
        match self {
            SignedTransaction::Election(signed) => signed.inputs(),
            SignedTransaction::Vote(signed) => signed.inputs(),
            SignedTransaction::SecretShare(signed) => signed.inputs(),
            SignedTransaction::Decryption(signed) => signed.inputs(),
        }
    }

    pub fn validate<S: Store>(&self, s: &S) -> Result<(), ValidationError> {
        match self {
            SignedTransaction::Election(tx) => tx.validate(s),
            SignedTransaction::Vote(tx) => tx.validate(s),
            SignedTransaction::SecretShare(tx) => tx.validate(s),
            SignedTransaction::Decryption(tx) => tx.validate(s),
        }
    }
}

/// This trait should be considered sealed and should not be implemented outside this crate
#[doc(hidden)]
pub trait Signable: Serialize {
    fn id(&self) -> Identifier;
    fn public(&self) -> Option<PublicKey>;
    fn inputs(&self) -> Vec<Identifier>;
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError>;

    fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("cryptoballot: Unexpected error serializing transaction")
    }
}

/// A generic signed transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signed<T: Signable + Serialize> {
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

    /// Verify the signature and validate the transaction
    pub fn validate<S: Store>(&self, store: &S) -> Result<(), ValidationError> {
        self.verify_signature()?;
        self.validate_tx(store)?;

        Ok(())
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identifier {
    pub election_id: [u8; 15],
    pub transaction_type: TransactionType,
    pub unique_id: Option<[u8; 16]>,
}

impl Identifier {
    /// Creat a new Identifier
    pub fn new(
        election_id: Identifier,
        transaction_type: TransactionType,
        unique_info: &[u8],
    ) -> Self {
        let election_id = election_id.election_id;
        let unique_id: [u8; 16] = sha2::Sha512::digest(unique_info)[0..16].try_into().unwrap();
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

    pub fn to_array(&self) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0; 32];
        bytes[0..15].clone_from_slice(&self.election_id);
        bytes[15] = self.transaction_type as u8;
        if let Some(unique_id) = self.unique_id {
            bytes[16..32].clone_from_slice(&unique_id);
        }
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = self.to_array();
        bytes.to_vec()
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

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let election_ord = self.election_id.cmp(&other.election_id);

        if let Ordering::Equal = election_ord {
            let tx_type = self.transaction_type as u8;
            let other_tx_type = other.transaction_type as u8;
            let tx_type_ord = tx_type.cmp(&other_tx_type);
            if let Ordering::Equal = tx_type_ord {
                Some(self.unique_id.cmp(&other.unique_id))
            } else {
                Some(tx_type_ord)
            }
        } else {
            Some(election_ord)
        }
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        let election_ord = self.election_id.cmp(&other.election_id);

        if let Ordering::Equal = election_ord {
            let tx_type = self.transaction_type as u8;
            let other_tx_type = other.transaction_type as u8;
            let tx_type_ord = tx_type.cmp(&other_tx_type);
            if let Ordering::Equal = tx_type_ord {
                self.unique_id.cmp(&other.unique_id)
            } else {
                tx_type_ord
            }
        } else {
            election_ord
        }
    }
}

impl From<Identifier> for [u8; 32] {
    fn from(item: Identifier) -> Self {
        item.to_array()
    }
}

/// A transaction type
// TODO: Maybe make Election = 0 to align with identifiers in merkle-tree
#[derive(Serialize, Deserialize, TryFromPrimitive, Copy, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TransactionType {
    Election = 1,
    Vote = 2,
    SecretShare = 3,
    Decryption = 4,
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match self {
            TransactionType::Election => "Election",
            TransactionType::Vote => "Vote",
            TransactionType::SecretShare => "SecretShare",
            TransactionType::Decryption => "Decryption",
        };
        write!(f, "{}", name)
    }
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

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_identifier() {
        assert!(TransactionType::Election as u8 == 1);
        assert!(TransactionType::Vote as u8 == 2);
        assert!(TransactionType::SecretShare as u8 == 3);
        assert!(TransactionType::Decryption as u8 == 4);

        let election_id = Identifier::new_for_election();
        let election_id_bytes = election_id.to_bytes();
        assert_eq!(election_id_bytes[15], 1);

        let stringed = election_id.to_string();
        let from_string = Identifier::from_str(&stringed).unwrap();

        assert_eq!(election_id, from_string);
    }
}
