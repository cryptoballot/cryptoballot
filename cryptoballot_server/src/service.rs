use exonum::runtime::{ExecutionContext, ExecutionError};
use exonum_derive::{exonum_interface, interface_method, ServiceDispatcher, ServiceFactory};
use exonum_rust_runtime::{api::ServiceApiBuilder, DefaultInstance, Service};

use crate::api::CryptoballotApi;
use cryptoballot::{SignedTransaction, Store};
use cryptoballot_exonum::{Transaction, TransactionSchema};
use exonum_rust_runtime::AfterCommitContext;
use std::sync::{Arc, Mutex};

lazy_static! {
    pub static ref DEPENDENT_TXS: Arc<Mutex<Vec<SignedTransaction>>> =
        Arc::new(Mutex::new(Vec::new()));
}

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
#[service_factory(proto_sources = "cryptoballot_exonum::proto")]
pub struct CryptoballotService;

impl CryptoballotInterface<ExecutionContext<'_>> for CryptoballotService {
    type Output = Result<(), ExecutionError>;

    fn submit_tx(&self, context: ExecutionContext<'_>, tx: Transaction) -> Self::Output {
        let id = tx.id.clone();
        if let Err(err) = cryptoballot_exonum::verify_and_store(context, tx) {
            eprintln!("Transaction verfication error for {}: {}", &id, err);
            return Err(err.into());
        }

        Ok(())
    }
}

impl Service for CryptoballotService {
    fn wire_api(&self, _builder: &mut ServiceApiBuilder) {
        CryptoballotApi::wire(_builder);
    }

    fn after_commit(&self, ctx: AfterCommitContext) {
        let blockchain_data = ctx.data().for_core();

        // Check if we need to process any pending dependent transactions from the last block
        {
            let mut stored_dependent_txs = DEPENDENT_TXS.lock().unwrap();
            if stored_dependent_txs.len() != 0 {
                println!(
                    "Submitting {} dependent tx on block height {}",
                    stored_dependent_txs.len(),
                    blockchain_data.height()
                );

                let broadcaster = ctx.generic_broadcaster().blocking();
                for dependent_tx in stored_dependent_txs.drain(0..) {
                    let exonum_tx: Transaction = dependent_tx.into();
                    broadcaster.submit_tx((), exonum_tx).ok();
                }
            }
        }

        // TODO: Check instance status and do something if we're frozen or stopped etc.
        //       Also do nothing if we're just an auditor and not a full peer.

        // Always process one block behind, so schema storage is always caught up
        let block_transactions =
            blockchain_data.block_transactions(blockchain_data.height().previous());

        if block_transactions.len() != 0 {
            println!(
                "Processing {} tx on block height {}",
                block_transactions.len(),
                blockchain_data.height().previous()
            );

            let all_txs = blockchain_data.transactions();
            let schema = TransactionSchema::new(ctx.service_data());

            let broadcaster = ctx.generic_broadcaster().blocking();

            for tx_hash in block_transactions.into_iter() {
                if let Some(raw_tx) = all_txs.get(&tx_hash) {
                    if let Ok(exonum_tx) = raw_tx.payload().parse::<Transaction>() {
                        let id = match exonum_tx.id.parse() {
                            Ok(id) => id,
                            Err(_) => {
                                eprintln!("Error parsing id {}", exonum_tx.id);
                                continue;
                            }
                        };
                        if let Some(tx) = schema.get_transaction(id) {
                            let tx_json = serde_json::to_string_pretty(&tx).unwrap();
                            println!("{}", tx_json);

                            let dependent_txs =
                                crate::tasks::generate_transactions(&tx, &schema).unwrap();

                            // TODO: Vote decryptions in batches
                            // let mut stored_dependent_txs = DEPENDENT_TXS.lock().unwrap();
                            for dependent_tx in dependent_txs {
                                if schema.get_transaction(dependent_tx.id()).is_none() {
                                    println!(
                                        "Broadcasting dependent {} {}",
                                        dependent_tx.transaction_type(),
                                        dependent_tx.id()
                                    );

                                    let exonum_tx = dependent_tx.into();
                                    broadcaster.submit_tx((), exonum_tx).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// Specify default instantiation parameters for the service.
impl DefaultInstance for CryptoballotService {
    const INSTANCE_ID: u32 = cryptoballot_exonum::CRYPTOBALLOT_SERVICE_ID;
    const INSTANCE_NAME: &'static str = "cryptoballot";
}
