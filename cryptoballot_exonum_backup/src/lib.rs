// Copyright 2020 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Demo [Exonum][exonum] service implementing a simple cryptocurrency.
//! See [the documentation][docs] for a detailed step-by-step guide how to approach this demo,
//! and [the repository README][readme] on how to use, test, and contribute to it.
//!
//! **Note.** The service in this crate is intended for demo purposes only. It is not intended
//! for use in production.
//!
//! [exonum]: https://github.com/exonum/exonum
//! [docs]: https://exonum.com/doc/version/latest/get-started/create-service
//! [readme]: https://github.com/exonum/cryptocurrency#readme

#![deny(
    missing_debug_implementations,
    missing_docs,
    unsafe_code,
    bare_trait_objects
)]

#[macro_use]
extern crate serde_derive; // Required for Protobuf.

pub mod proto;

/// Persistent data.
pub mod schema {
    use cryptoballot::{Identifier, SignedTransaction, TransactionType};
    use exonum::{
        crypto::PublicKey,
        merkledb::{
            access::{Access, FromAccess},
            MapIndex,
        },
    };
    use exonum_derive::{BinaryValue, FromAccess, ObjectHash};
    use exonum_proto::ProtobufConvert;

    use crate::proto;

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

        fn get_multiple(
            &self,
            election_id: Identifier,
            tx_type: TransactionType,
        ) -> Vec<SignedTransaction> {
            let mut results = Vec::new();

            let mut start = election_id.clone();
            start.transaction_type = tx_type;
            let start = start.to_string();

            for (k, v) in self.transactions.iter_from(&start) {
                // If we're an election type, and we're into the next election, break
                if tx_type == TransactionType::Election && &start[0..32] != &k[0..32] {
                    break;
                }

                // If we're into the next type, break
                if tx_type.hex_string() != &k[32..34] {
                    break;
                }

                if let Ok(decoded) = SignedTransaction::from_bytes(&v.data) {
                    results.push(decoded)
                }
            }
            results
        }
    }
}

/// Contract errors.
pub mod errors {
    use exonum_derive::ExecutionFail;

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
}

/// Contracts.
pub mod contracts {
    use exonum::runtime::{ExecutionContext, ExecutionError};
    use exonum_derive::{exonum_interface, interface_method, ServiceDispatcher, ServiceFactory};
    use exonum_rust_runtime::{api::ServiceApiBuilder, DefaultInstance, Service};

    use crate::{
        api::CryptoballotApi,
        errors::Error,
        schema::{Transaction, TransactionSchema},
    };

    /// Cryptocurrency service transactions.
    #[exonum_interface]
    pub trait CryptoballotInterface<Ctx> {
        /// Output of the methods in this interface.
        type Output;

        /// Submits a transaction
        #[interface_method(id = 0)]
        fn submit_tx(&self, ctx: Ctx, tx: Transaction) -> Self::Output;
    }

    /// Cryptocurrency service implementation.
    #[derive(Debug, ServiceFactory, ServiceDispatcher)]
    #[service_dispatcher(implements("CryptoballotInterface"))]
    #[service_factory(proto_sources = "crate::proto")]
    pub struct CryptoballotService;

    impl CryptoballotInterface<ExecutionContext<'_>> for CryptoballotService {
        type Output = Result<(), ExecutionError>;

        fn submit_tx(&self, context: ExecutionContext<'_>, tx: Transaction) -> Self::Output {
            let author = context
                .caller()
                .author()
                .expect("Missing public key of submitter");

            let mut schema = TransactionSchema::new(context.service_data());
            if schema.transactions.get(&tx.id).is_none() {
                println!("Creating tx: {:?}", tx);

                let unpacked_tx = match cryptoballot::SignedTransaction::from_bytes(&tx.data) {
                    Ok(tx) => tx,
                    Err(_) => {
                        return Err(Error::InvalidTransactionFormat.into());
                    }
                };

                if let Some(pkey) = unpacked_tx.public() {
                    if pkey.as_bytes() != &author.as_bytes() {
                        return Err(Error::AuthorPublicKeyMismatch.into());
                    }
                }

                if unpacked_tx.verify_signature().is_err() {
                    return Err(Error::VerificationFailed.into());
                }

                if unpacked_tx.validate(&schema).is_err() {
                    return Err(Error::VerificationFailed.into());
                }

                // TODO: Election Authority public key for election tx

                // All checks pass
                schema.transactions.put(&tx.id.clone(), tx);
                Ok(())
            } else {
                Err(Error::TransactionAlreadyExists.into())
            }
        }
    }

    impl Service for CryptoballotService {
        fn wire_api(&self, builder: &mut ServiceApiBuilder) {
            CryptoballotApi::wire(builder);
        }
    }

    // Specify default instantiation parameters for the service.
    impl DefaultInstance for CryptoballotService {
        const INSTANCE_ID: u32 = 101;
        const INSTANCE_NAME: &'static str = "cryptoballot";
    }
}

/// Cryptoballot API implementation.
pub mod api {
    use exonum::crypto::PublicKey;
    use exonum_rust_runtime::api::{self, ServiceApiBuilder, ServiceApiState};

    use crate::schema::{Transaction, TransactionSchema};

    /// Public service API description.
    #[derive(Debug, Clone, Copy)]
    pub struct CryptoballotApi;

    /// The structure describes the query parameters for the `get_wallet` endpoint.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TxQuery {
        /// Transaction ID
        pub id: String,
    }

    impl CryptoballotApi {
        /// Endpoint for getting a single wallet.
        pub async fn get_tx(state: ServiceApiState, query: TxQuery) -> api::Result<Transaction> {
            let schema = TransactionSchema::new(state.service_data());
            schema
                .transactions
                .get(&query.id)
                .ok_or_else(|| api::Error::not_found().title("Transaction not found"))
        }

        /// Endpoint for dumping all wallets from the storage.
        pub async fn get_all(state: ServiceApiState, _query: ()) -> api::Result<Vec<Transaction>> {
            let schema = TransactionSchema::new(state.service_data());
            Ok(schema.transactions.values().collect())
        }

        /// `ServiceApiBuilder` facilitates conversion between read requests and REST
        /// endpoints.
        pub fn wire(builder: &mut ServiceApiBuilder) {
            // Binds handlers to specific routes.
            builder
                .public_scope()
                .endpoint("exonum/tx", Self::get_tx)
                .endpoint("exonum/txs", Self::get_all);
        }
    }
}
