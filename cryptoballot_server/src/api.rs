use exonum_rust_runtime::api::{self, ServiceApiBuilder, ServiceApiState};

use cryptoballot::SignedTransaction;
use cryptoballot_exonum::TransactionSchema;

/// Public service API description.
#[derive(Debug, Clone, Copy)]
pub struct CryptoballotApi;

/// The structure describes the query parameters for the `get_wallet` endpoint.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxQuery {
    /// Transaction ID
    pub id: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionsQuery {
    /// Prefix
    pub prefix: Option<String>,
}

impl CryptoballotApi {
    /// Endpoint for getting a single transaction.
    pub async fn get_tx(state: ServiceApiState, query: TxQuery) -> api::Result<SignedTransaction> {
        use std::convert::TryInto;

        let schema = TransactionSchema::new(state.service_data());
        let exonum_tx = schema
            .transactions
            .get(&query.id)
            .ok_or_else(|| api::Error::not_found().title("Transaction not found"))?;

        Ok(exonum_tx
            .try_into()
            .map_err(|_| api::Error::internal("cryptoballot_server: Bad Transaction Format"))?)
    }

    /// Endpoint for dumping all transactions from the storage.
    pub async fn get_all(
        state: ServiceApiState,
        query: TransactionsQuery,
    ) -> api::Result<Vec<SignedTransaction>> {
        use std::convert::TryInto;

        let schema = TransactionSchema::new(state.service_data());

        let mut txs = Vec::new();

        if let Some(prefix) = query.prefix {
            let start = format!("{:0<64}", prefix);
            for (k, exonum_tx) in schema.transactions.iter_from(&start) {
                if !k.starts_with(&prefix) {
                    break;
                }
                txs.push(exonum_tx.try_into().map_err(|_| {
                    api::Error::internal("cryptoballot_server: Bad Transaction Format")
                })?)
            }
        } else {
            for exonum_tx in schema.transactions.values() {
                txs.push(exonum_tx.try_into().map_err(|_| {
                    api::Error::internal("cryptoballot_server: Bad Transaction Format")
                })?)
            }
        }

        Ok(txs)
    }

    /// Endpoint for dumping all wallets from the storage.
    pub async fn public_key(
        state: ServiceApiState,
        _query: (),
    ) -> api::Result<exonum_crypto::PublicKey> {
        Ok(state.service_key())
    }

    /// `ServiceApiBuilder` facilitates conversion between read requests and REST
    /// endpoints.
    pub fn wire(builder: &mut ServiceApiBuilder) {
        //binds handlers to specific routes.
        builder
            .public_scope()
            .endpoint("transaction", Self::get_tx)
            .endpoint("transactions", Self::get_all)
            .endpoint("public_key", Self::public_key);
    }
}
