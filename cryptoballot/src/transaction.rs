use crate::*;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::convert::AsRef;
use std::convert::From;
use std::convert::TryFrom;
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
    KeyGenCommitment(KeyGenCommitmentTransaction),
    KeyGenShare(KeyGenShareTransaction),
    KeyGenPublicKey(KeyGenPublicKeyTransaction),
    EncryptionKey(EncryptionKeyTransaction),
    Vote(VoteTransaction),
    VotingEnd(VotingEndTransaction),
    Mix(MixTransaction),
    PartialDecryption(PartialDecryptionTransaction),
    Decryption(DecryptionTransaction),
}

impl Transaction {
    /// Get the transaction type
    pub fn transaction_type(&self) -> TransactionType {
        match self {
            Transaction::Election(_) => TransactionType::Election,
            Transaction::KeyGenCommitment(_) => TransactionType::KeyGenCommitment,
            Transaction::KeyGenShare(_) => TransactionType::KeyGenShare,
            Transaction::KeyGenPublicKey(_) => TransactionType::KeyGenPublicKey,
            Transaction::EncryptionKey(_) => TransactionType::EncryptionKey,
            Transaction::Vote(_) => TransactionType::Vote,
            Transaction::VotingEnd(_) => TransactionType::VotingEnd,
            Transaction::Mix(_) => TransactionType::Mix,
            Transaction::PartialDecryption(_) => TransactionType::PartialDecryption,
            Transaction::Decryption(_) => TransactionType::Decryption,
        }
    }

    /// Get the transaction ID
    pub fn id(&self) -> Identifier {
        match self {
            Transaction::Election(tx) => tx.id,
            Transaction::KeyGenCommitment(tx) => tx.id,
            Transaction::KeyGenShare(tx) => tx.id,
            Transaction::KeyGenPublicKey(tx) => tx.id,
            Transaction::EncryptionKey(tx) => tx.id,
            Transaction::Vote(tx) => tx.id,
            Transaction::VotingEnd(tx) => tx.id,
            Transaction::Mix(tx) => tx.id,
            Transaction::PartialDecryption(tx) => tx.id,
            Transaction::Decryption(tx) => tx.id,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    pub fn validate_tx<S: Store>(&self, s: &S) -> Result<(), ValidationError> {
        match self {
            Transaction::Election(tx) => tx.validate_tx(s),
            Transaction::KeyGenCommitment(tx) => tx.validate_tx(s),
            Transaction::KeyGenShare(tx) => tx.validate_tx(s),
            Transaction::KeyGenPublicKey(tx) => tx.validate_tx(s),
            Transaction::EncryptionKey(tx) => tx.validate_tx(s),
            Transaction::Vote(tx) => tx.validate_tx(s),
            Transaction::VotingEnd(tx) => tx.validate_tx(s),
            Transaction::Mix(tx) => tx.validate_tx(s),
            Transaction::PartialDecryption(tx) => tx.validate_tx(s),
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
    KeyGenCommitment(Signed<KeyGenCommitmentTransaction>),
    KeyGenShare(Signed<KeyGenShareTransaction>),
    KeyGenPublicKey(Signed<KeyGenPublicKeyTransaction>),
    EncryptionKey(Signed<EncryptionKeyTransaction>),
    Vote(Signed<VoteTransaction>),
    VotingEnd(Signed<VotingEndTransaction>),
    Mix(Signed<MixTransaction>),
    PartialDecryption(Signed<PartialDecryptionTransaction>),
    Decryption(Signed<DecryptionTransaction>),
}

impl SignedTransaction {
    /// Get the transaction type
    pub fn transaction_type(&self) -> TransactionType {
        match self {
            SignedTransaction::Election(_) => TransactionType::Election,
            SignedTransaction::KeyGenCommitment(_) => TransactionType::KeyGenCommitment,
            SignedTransaction::KeyGenShare(_) => TransactionType::KeyGenShare,
            SignedTransaction::KeyGenPublicKey(_) => TransactionType::KeyGenPublicKey,
            SignedTransaction::EncryptionKey(_) => TransactionType::EncryptionKey,
            SignedTransaction::Vote(_) => TransactionType::Vote,
            SignedTransaction::VotingEnd(_) => TransactionType::VotingEnd,
            SignedTransaction::Mix(_) => TransactionType::Mix,
            SignedTransaction::PartialDecryption(_) => TransactionType::PartialDecryption,
            SignedTransaction::Decryption(_) => TransactionType::Decryption,
        }
    }

    /// Pack into bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("cryptoballot: Unexpected error packing transaction")
    }

    /// Unpack from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(serde_cbor::from_slice(bytes)?)
    }

    /// Get the transaction ID
    pub fn id(&self) -> Identifier {
        match self {
            SignedTransaction::Election(signed) => signed.tx.id,
            SignedTransaction::KeyGenCommitment(signed) => signed.tx.id,
            SignedTransaction::KeyGenShare(signed) => signed.tx.id,
            SignedTransaction::KeyGenPublicKey(signed) => signed.tx.id,
            SignedTransaction::EncryptionKey(signed) => signed.tx.id,
            SignedTransaction::Vote(signed) => signed.tx.id,
            SignedTransaction::VotingEnd(signed) => signed.tx.id,
            SignedTransaction::Mix(signed) => signed.tx.id,
            SignedTransaction::PartialDecryption(signed) => signed.tx.id,
            SignedTransaction::Decryption(signed) => signed.tx.id,
        }
    }

    /// Validate the transaction. This does the following:
    /// 1. Checks that the id-type matches the transaction-type
    /// 2. Validates the signature
    /// 3. Validates the transaction against the store
    pub fn validate<S: Store>(&self, s: &S) -> Result<(), ValidationError> {
        if self.id().transaction_type != self.transaction_type() {
            return Err(ValidationError::MismatchedTransactionType);
        }
        match self {
            SignedTransaction::Election(tx) => tx.validate(s),
            SignedTransaction::KeyGenCommitment(tx) => tx.validate(s),
            SignedTransaction::KeyGenShare(tx) => tx.validate(s),
            SignedTransaction::KeyGenPublicKey(tx) => tx.validate(s),
            SignedTransaction::EncryptionKey(tx) => tx.validate(s),
            SignedTransaction::Vote(tx) => tx.validate(s),
            SignedTransaction::VotingEnd(tx) => tx.validate(s),
            SignedTransaction::Mix(tx) => tx.validate(s),
            SignedTransaction::PartialDecryption(tx) => tx.validate(s),
            SignedTransaction::Decryption(tx) => tx.validate(s),
        }
    }

    pub fn verify_signature(&self) -> Result<(), ValidationError> {
        match self {
            SignedTransaction::Election(tx) => tx.verify_signature(),
            SignedTransaction::KeyGenCommitment(tx) => tx.verify_signature(),
            SignedTransaction::KeyGenShare(tx) => tx.verify_signature(),
            SignedTransaction::KeyGenPublicKey(tx) => tx.verify_signature(),
            SignedTransaction::EncryptionKey(tx) => tx.verify_signature(),
            SignedTransaction::Vote(tx) => tx.verify_signature(),
            SignedTransaction::VotingEnd(tx) => tx.verify_signature(),
            SignedTransaction::Mix(tx) => tx.verify_signature(),
            SignedTransaction::PartialDecryption(tx) => tx.verify_signature(),
            SignedTransaction::Decryption(tx) => tx.verify_signature(),
        }
    }

    pub fn public(&self) -> Option<PublicKey> {
        match self {
            SignedTransaction::Election(tx) => tx.public(),
            SignedTransaction::KeyGenCommitment(tx) => tx.public(),
            SignedTransaction::KeyGenShare(tx) => tx.public(),
            SignedTransaction::KeyGenPublicKey(tx) => tx.public(),
            SignedTransaction::EncryptionKey(tx) => tx.public(),
            SignedTransaction::Vote(tx) => tx.public(),
            SignedTransaction::VotingEnd(tx) => tx.public(),
            SignedTransaction::Mix(tx) => tx.public(),
            SignedTransaction::PartialDecryption(tx) => tx.public(),
            SignedTransaction::Decryption(tx) => tx.public(),
        }
    }
}

/// All CryptoBallot transactions implement this trait
pub trait CryptoBallotTransaction: Serialize + sealed::Sealed {
    /// Get the transaction ID
    fn id(&self) -> Identifier;

    /// Get the transaction public key, if there is one
    fn public(&self) -> Option<PublicKey>;

    /// Get the transaction election ID
    fn election_id(&self) -> Identifier;

    /// Get the transaction Type
    fn tx_type() -> TransactionType;

    /// Validate the transcation
    fn validate_tx<S: Store>(&self, store: &S) -> Result<(), ValidationError>;

    /// Serialize the transaction to bytes for signing
    fn as_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).expect("cryptoballot: Unexpected error serializing transaction")
    }
}

/// Seal CryptoBallot Transaction so they can't be implemented outside this crate
mod sealed {
    pub trait Sealed {}

    impl Sealed for crate::ElectionTransaction {}
    impl Sealed for crate::KeyGenCommitmentTransaction {}
    impl Sealed for crate::KeyGenShareTransaction {}
    impl Sealed for crate::KeyGenPublicKeyTransaction {}
    impl Sealed for crate::EncryptionKeyTransaction {}
    impl Sealed for crate::VoteTransaction {}
    impl Sealed for crate::VotingEndTransaction {}
    impl Sealed for crate::MixTransaction {}
    impl Sealed for crate::PartialDecryptionTransaction {}
    impl Sealed for crate::DecryptionTransaction {}
}

/// A generic signed transaction
#[derive(Serialize, Deserialize, Clone)]
pub struct Signed<T: CryptoBallotTransaction + Serialize> {
    pub tx: T,

    #[serde(with = "EdSignatureHex")]
    pub sig: Signature,
}

impl<T: CryptoBallotTransaction + Serialize> Signed<T> {
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

impl<T: CryptoBallotTransaction + Serialize> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {
        &self.tx
    }
}

impl<T: CryptoBallotTransaction + Serialize> Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

/// Transaction identifier
///
/// The identifier defines the election, transction-type, and a unique identifier.
///
/// TODO: Entire aligned-struct is 40 bytes, larger than our ideal Copy limit of 32 bytes
///       We should combine election_id and tx_type and have utility functions
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identifier {
    pub election_id: [u8; 15],             // Will align to 16 bytes
    pub transaction_type: TransactionType, // Will align to 8 bytes
    pub unique_info: [u8; 16],             // Will align to 16 bytes
}

impl Identifier {
    /// Creat a new Identifier
    pub fn new(
        election_id: Identifier,
        transaction_type: TransactionType,
        unique_info: Option<[u8; 16]>,
    ) -> Self {
        let unique_info = unique_info.unwrap_or([0; 16]);
        let election_id = election_id.election_id;

        Identifier {
            election_id,
            transaction_type,
            unique_info,
        }
    }

    // Create a new identifier that starts at the start of a transaction type
    pub fn start(
        election_id: Identifier,
        transaction_type: TransactionType,
        unique_info_mask: Option<&[u8]>,
    ) -> Self {
        let mut unique_info = [0; 16];
        let unique_info_mask = unique_info_mask.unwrap_or(&[]);
        unique_info[0..unique_info_mask.len()].copy_from_slice(unique_info_mask);

        Self {
            election_id: election_id.election_id,
            transaction_type: transaction_type,
            unique_info,
        }
    }

    // Create a new identifier that marks the end of a transaction type
    pub fn end(
        election_id: Identifier,
        transaction_type: TransactionType,
        unique_info_mask: Option<&[u8]>,
    ) -> Self {
        let mut unique_info = [255; 16];
        let unique_info_mask = unique_info_mask.unwrap_or(&[]);
        unique_info[0..unique_info_mask.len()].copy_from_slice(unique_info_mask);

        Self {
            election_id: election_id.election_id,
            transaction_type: transaction_type,
            unique_info,
        }
    }

    /// Creat a new Identifier from an election-id string
    /// Returns None when election_id is invalid
    pub fn new_from_str_id(
        election_id: &str,
        transaction_type: TransactionType,
        unique_info: Option<[u8; 16]>,
    ) -> Option<Self> {
        let unique_info = unique_info.unwrap_or([0; 16]);

        let election_id_bits = match hex::decode(election_id) {
            Ok(bits) => bits,
            Err(_) => return None,
        };

        if election_id_bits.len() < 15 {
            return None;
        }

        let election_id = Self {
            election_id: election_id_bits[0..15].try_into().unwrap(),
            transaction_type: TransactionType::Election,
            unique_info: [0; 16],
        };
        return Some(Self::new(election_id, transaction_type, Some(unique_info)));
    }

    pub fn to_array(&self) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0; 32];
        bytes[0..15].clone_from_slice(&self.election_id);
        bytes[15] = self.transaction_type as u8;
        bytes[16..32].clone_from_slice(&self.unique_info);
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = self.to_array();
        bytes.to_vec()
    }

    pub fn election_id_string(&self) -> String {
        hex::encode(self.election_id)
    }
}

impl FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| Error::IdentifierBadHex)?;

        if bytes.len() != 32 && bytes.len() != 16 {
            return Err(Error::IdentifierBadLen);
        }

        // These unwraps are OK - we know the length is valid
        let election_id: [u8; 15] = bytes[0..15].try_into().unwrap();
        let transaction_type = TransactionType::try_from_primitive(bytes[15]).unwrap();

        let unique_info: [u8; 16] = bytes[16..].try_into().unwrap();

        Ok(Identifier {
            election_id,
            transaction_type,
            unique_info,
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
                Some(self.unique_info.cmp(&other.unique_info))
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
                self.unique_info.cmp(&other.unique_info)
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
#[derive(
    Serialize, Deserialize, TryFromPrimitive, IntoPrimitive, Copy, Debug, Clone, PartialEq, Eq, Hash,
)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TransactionType {
    Election = 1,
    KeyGenCommitment = 2,
    KeyGenShare = 3,
    KeyGenPublicKey = 4,
    EncryptionKey = 5,
    Vote = 6,
    VotingEnd = 7,
    Mix = 8,
    PartialDecryption = 9,
    Decryption = 10,
}

impl TransactionType {
    pub fn hex_string(&self) -> &str {
        match self {
            TransactionType::Election => "01",
            TransactionType::KeyGenCommitment => "02",
            TransactionType::KeyGenShare => "03",
            TransactionType::KeyGenPublicKey => "04",
            TransactionType::EncryptionKey => "05",
            TransactionType::Vote => "06",
            TransactionType::VotingEnd => "07",
            TransactionType::Mix => "08",
            TransactionType::PartialDecryption => "09",
            TransactionType::Decryption => "0a",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            TransactionType::Election => "election",
            TransactionType::KeyGenCommitment => "key_gen_commitment",
            TransactionType::KeyGenShare => "key_gen_share",
            TransactionType::KeyGenPublicKey => "key_gen_public_key",
            TransactionType::EncryptionKey => "encryption_key",
            TransactionType::Vote => "vote",
            TransactionType::VotingEnd => "voting_end",
            TransactionType::Mix => "mix",
            TransactionType::PartialDecryption => "partial_decryption",
            TransactionType::Decryption => "decryption",
        }
    }

    pub fn from_u8(numeric: u8) -> Option<Self> {
        Self::try_from(numeric).ok()
    }
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = self.name();
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

impl From<SignedTransaction> for Signed<KeyGenCommitmentTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenCommitment(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<KeyGenShareTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenShare(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<KeyGenPublicKeyTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenPublicKey(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<EncryptionKeyTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::EncryptionKey(tx) => tx,
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

impl From<SignedTransaction> for Signed<VotingEndTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::VotingEnd(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<MixTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Mix(tx) => tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for Signed<PartialDecryptionTransaction> {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::PartialDecryption(tx) => tx,
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

impl From<SignedTransaction> for ElectionTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Election(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for KeyGenCommitmentTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenCommitment(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for KeyGenShareTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenShare(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for KeyGenPublicKeyTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::KeyGenPublicKey(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for EncryptionKeyTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::EncryptionKey(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for VoteTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Vote(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for VotingEndTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::VotingEnd(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for MixTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Mix(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for DecryptionTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::Decryption(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<SignedTransaction> for PartialDecryptionTransaction {
    fn from(tx: SignedTransaction) -> Self {
        match tx {
            SignedTransaction::PartialDecryption(tx) => tx.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl From<Signed<ElectionTransaction>> for SignedTransaction {
    fn from(tx: Signed<ElectionTransaction>) -> Self {
        SignedTransaction::Election(tx)
    }
}

impl From<Signed<KeyGenCommitmentTransaction>> for SignedTransaction {
    fn from(tx: Signed<KeyGenCommitmentTransaction>) -> Self {
        SignedTransaction::KeyGenCommitment(tx)
    }
}

impl From<Signed<KeyGenShareTransaction>> for SignedTransaction {
    fn from(tx: Signed<KeyGenShareTransaction>) -> Self {
        SignedTransaction::KeyGenShare(tx)
    }
}

impl From<Signed<KeyGenPublicKeyTransaction>> for SignedTransaction {
    fn from(tx: Signed<KeyGenPublicKeyTransaction>) -> Self {
        SignedTransaction::KeyGenPublicKey(tx)
    }
}

impl From<Signed<EncryptionKeyTransaction>> for SignedTransaction {
    fn from(tx: Signed<EncryptionKeyTransaction>) -> Self {
        SignedTransaction::EncryptionKey(tx)
    }
}

impl From<Signed<VoteTransaction>> for SignedTransaction {
    fn from(tx: Signed<VoteTransaction>) -> Self {
        SignedTransaction::Vote(tx)
    }
}

impl From<Signed<VotingEndTransaction>> for SignedTransaction {
    fn from(tx: Signed<VotingEndTransaction>) -> Self {
        SignedTransaction::VotingEnd(tx)
    }
}

impl From<Signed<MixTransaction>> for SignedTransaction {
    fn from(tx: Signed<MixTransaction>) -> Self {
        SignedTransaction::Mix(tx)
    }
}

impl From<Signed<PartialDecryptionTransaction>> for SignedTransaction {
    fn from(tx: Signed<PartialDecryptionTransaction>) -> Self {
        SignedTransaction::PartialDecryption(tx)
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

impl AsRef<KeyGenCommitmentTransaction> for SignedTransaction {
    fn as_ref(&self) -> &KeyGenCommitmentTransaction {
        match self {
            SignedTransaction::KeyGenCommitment(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<KeyGenShareTransaction> for SignedTransaction {
    fn as_ref(&self) -> &KeyGenShareTransaction {
        match self {
            SignedTransaction::KeyGenShare(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<KeyGenPublicKeyTransaction> for SignedTransaction {
    fn as_ref(&self) -> &KeyGenPublicKeyTransaction {
        match self {
            SignedTransaction::KeyGenPublicKey(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<EncryptionKeyTransaction> for SignedTransaction {
    fn as_ref(&self) -> &EncryptionKeyTransaction {
        match self {
            SignedTransaction::EncryptionKey(signed) => &signed.tx,
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

impl AsRef<VotingEndTransaction> for SignedTransaction {
    fn as_ref(&self) -> &VotingEndTransaction {
        match self {
            SignedTransaction::VotingEnd(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<MixTransaction> for SignedTransaction {
    fn as_ref(&self) -> &MixTransaction {
        match self {
            SignedTransaction::Mix(signed) => &signed.tx,
            _ => panic!("wrong transaction type expected"),
        }
    }
}

impl AsRef<PartialDecryptionTransaction> for SignedTransaction {
    fn as_ref(&self) -> &PartialDecryptionTransaction {
        match self {
            SignedTransaction::PartialDecryption(signed) => &signed.tx,
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
    use rand::Rng;

    #[test]
    fn test_identifier() {
        assert!(TransactionType::Election as u8 == 1);
        assert!(TransactionType::KeyGenCommitment as u8 == 2);
        assert!(TransactionType::KeyGenShare as u8 == 3);
        assert!(TransactionType::KeyGenPublicKey as u8 == 4);
        assert!(TransactionType::EncryptionKey as u8 == 5);
        assert!(TransactionType::Vote as u8 == 6);
        assert!(TransactionType::VotingEnd as u8 == 7);
        assert!(TransactionType::Mix as u8 == 8);
        assert!(TransactionType::PartialDecryption as u8 == 9);
        assert!(TransactionType::Decryption as u8 == 10);

        let mut rng = rand::thread_rng();
        let election_id = ElectionTransaction::build_id(rng.gen());
        let election_id_bytes = election_id.to_bytes();
        assert_eq!(election_id_bytes[15], 1);

        let stringed = election_id.to_string();
        let from_string = Identifier::from_str(&stringed).unwrap();

        assert_eq!(election_id, from_string);
    }
}
