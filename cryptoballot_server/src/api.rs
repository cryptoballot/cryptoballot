use exonum_rust_runtime::api::{self, ServiceApiBuilder, ServiceApiState};

use cryptoballot_exonum::{Transaction, TransactionSchema};

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
    /// Endpoint for getting a single transaction.
    pub async fn get_tx(state: ServiceApiState, query: TxQuery) -> api::Result<Transaction> {
        let schema = TransactionSchema::new(state.service_data());
        schema
            .transactions
            .get(&query.id)
            .ok_or_else(|| api::Error::not_found().title("Transaction not found"))
    }

    /// Endpoint for dumping all transactions from the storage.
    pub async fn get_all(state: ServiceApiState, _query: ()) -> api::Result<Vec<Transaction>> {
        let schema = TransactionSchema::new(state.service_data());
        Ok(schema.transactions.values().collect())
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
