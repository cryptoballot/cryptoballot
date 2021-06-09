use exonum::runtime::{ExecutionContext, ExecutionError};
use exonum_derive::{exonum_interface, interface_method, ServiceDispatcher, ServiceFactory};
use exonum_rust_runtime::{api::ServiceApiBuilder, DefaultInstance, Service};

use crate::api::CryptoballotApi;
use cryptoballot::SignedTransaction;
use cryptoballot_exonum::{Transaction, TransactionSchema};
use exonum::runtime::InstanceStatus;
use exonum_rust_runtime::AfterCommitContext;

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
        if let Err(err) = cryptoballot_exonum::verify_and_store(context, tx) {
            return Err(err.into());
        }

        Ok(())
    }
}

impl Service for CryptoballotService {
    fn wire_api(&self, _builder: &mut ServiceApiBuilder) {
        CryptoballotApi::wire(_builder);
    }

    fn after_commit(&self, ctx: AfterCommitContext<'_>) {
        if *ctx.status() != InstanceStatus::Active {
            return;
            // TODO: Store transaction for later when service is ready
            // after_commit should tick about once a second, even when there are no new txs
        }

        let blockchain_data = ctx.data().for_core();

        let block_transactions = blockchain_data.block_transactions(ctx.height());

        if block_transactions.len() != 0 {
            let schema = TransactionSchema::new(ctx.service_data());
            let all_txs = blockchain_data.transactions();
            let broadcaster = ctx.generic_broadcaster().blocking();

            for tx_hash in block_transactions.into_iter() {
                if let Some(raw_tx) = all_txs.get(&tx_hash) {
                    if let Ok(exonum_tx) = raw_tx.payload().parse::<Transaction>() {
                        if let Ok(tx) = SignedTransaction::from_bytes(&exonum_tx.data) {
                            let tx_json = serde_json::to_string_pretty(&tx).unwrap();
                            println!("{}", tx_json);

                            let dependent_txs = crate::tasks::generate_transactions(&tx, &schema);

                            for dependent_tx in dependent_txs {
                                let exonum_tx: Transaction = dependent_tx.into();
                                broadcaster.submit_tx((), exonum_tx).ok();
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
    const INSTANCE_ID: u32 = 101;
    const INSTANCE_NAME: &'static str = "cryptoballot";
}
