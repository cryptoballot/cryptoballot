#![deny(missing_debug_implementations, unsafe_code, bare_trait_objects)]

#[macro_use]
extern crate serde_derive; // Required for Protobuf.

use cryptoballot::{Identifier, SignedTransaction, TransactionType};
use exonum::messages::SignedMessage;
use exonum::messages::Verified;
use exonum::runtime::{AnyTx, CallInfo};
use exonum::{
    crypto::PublicKey,
    crypto::SecretKey,
    merkledb::{
        access::{Access, FromAccess},
        MapIndex,
    },
};
use exonum_derive::ExecutionFail;
use exonum_derive::{BinaryValue, FromAccess, ObjectHash};
use exonum_explorer::api::TransactionHex;
use exonum_proto::ProtobufConvert;

pub mod proto;

pub const CRYPTOBALLOT_SERVICE_ID: u32 = 5013;

/// Cryptoballot Transaction
#[derive(Clone, Debug, Serialize, Deserialize, ProtobufConvert, BinaryValue, ObjectHash)]
#[protobuf_convert(source = "proto::Transaction")]
pub struct Transaction {
    /// Public key of transaction owner
    pub pub_key: PublicKey,
    /// Transaction ID
    pub id: String,
    /// Transaction payload
    pub data: Vec<u8>,
}

impl Transaction {
    pub fn into_transaction_hex(self, public: PublicKey, secret: &SecretKey) -> TransactionHex {
        use exonum_merkledb::BinaryValue;

        let call_info = CallInfo::new(CRYPTOBALLOT_SERVICE_ID, 0);
        let any_tx = AnyTx::new(call_info, self.to_bytes().to_owned());
        let transaction = any_tx.sign(public, &secret);
        let tx_hex = TransactionHex::new(&transaction);

        tx_hex
    }
}

impl From<SignedTransaction> for Transaction {
    fn from(tx: SignedTransaction) -> Self {
        let pub_key = match tx.public() {
            Some(public) => PublicKey::from_slice(public.as_ref()).unwrap(),
            None => PublicKey::zero(),
        };

        Transaction {
            pub_key: pub_key,
            id: tx.id().to_string(),
            data: tx.as_bytes(),
        }
    }
}

impl std::convert::TryInto<SignedTransaction> for Transaction {
    type Error = cryptoballot::Error;

    fn try_into(self) -> Result<SignedTransaction, Self::Error> {
        SignedTransaction::from_bytes(&self.data)
    }
}

/// Schema of the key-value storage used by the demo cryptocurrency service.
#[derive(Debug, FromAccess)]
pub struct TransactionSchema<T: Access> {
    /// Correspondence of tx ids to the transaction payload
    pub transactions: MapIndex<T::Base, String, Transaction>,
}

impl<T: Access> TransactionSchema<T> {
    /// Creates a new schema.
    pub fn new(access: T) -> Self {
        Self::from_root(access).unwrap()
    }
}

impl<T: Access> cryptoballot::Store for TransactionSchema<T> {
    fn get_transaction(&self, id: Identifier) -> Option<SignedTransaction> {
        let key = id.to_string();
        let encoded_tx = self.transactions.get(&key);

        match encoded_tx {
            Some(encoded_tx) => SignedTransaction::from_bytes(&encoded_tx.data).ok(),
            None => None,
        }
    }

    fn range(&self, start: Identifier, exclusive_end: Identifier) -> Vec<SignedTransaction> {
        let mut results = Vec::new();

        let start = start.to_string();
        let end = exclusive_end.to_string();

        for (k, v) in self.transactions.iter_from(&start) {
            // If we're lexographically equal or larger than end, we've gone one past the end
            if k >= end {
                break;
            }

            if let Ok(decoded) = SignedTransaction::from_bytes(&v.data) {
                results.push(decoded)
            }
        }
        results
    }
}

/// Error codes emitted by `TxCreateWallet` and/or `TxTransfer` transactions during execution.
#[derive(Debug, ExecutionFail)]
pub enum Error {
    /// Transaction already exists.
    TransactionAlreadyExists = 0,

    /// Transaction author public key does not match Tranaction public key
    AuthorPublicKeyMismatch = 1,

    /// The public-key is not authorized to submit this transaction
    NotAuthorized = 2,

    /// Transaction Verification Failed
    VerificationFailed = 3,

    /// Invalid Transaction Format
    InvalidTransactionFormat = 4,
}

use exonum::runtime::ExecutionContext;

pub fn verify_and_store(context: ExecutionContext<'_>, tx: Transaction) -> Result<(), Error> {
    let author = context
        .caller()
        .author()
        .expect("Missing public key of submitter"); // TODO: Error not panic

    let mut schema = TransactionSchema::new(context.service_data());
    if schema.transactions.get(&tx.id).is_some() {
        return Err(Error::TransactionAlreadyExists);
    }

    println!("Creating tx: {:?}", tx);

    let unpacked_tx = match cryptoballot::SignedTransaction::from_bytes(&tx.data) {
        Ok(tx) => tx,
        Err(_) => {
            return Err(Error::InvalidTransactionFormat);
        }
    };

    if let Some(pkey) = unpacked_tx.public() {
        // TODO: Check that exonum public-key matches inner public-key if it exists
        //if pkey.as_bytes() != &author.as_bytes() {
        //    return Err(Error::AuthorPublicKeyMismatch);
        //}
    }

    if let Err(err) = unpacked_tx.verify_signature() {
        eprintln!("{}", err);
        return Err(Error::VerificationFailed);
    }

    if let Err(err) = unpacked_tx.validate(&schema) {
        eprintln!("{}", err);
        return Err(Error::VerificationFailed);
    }

    // TODO: Election Authority public key for election tx

    // All checks pass, store the transaction
    schema.transactions.put(&tx.id.clone(), tx);
    Ok(())
}
