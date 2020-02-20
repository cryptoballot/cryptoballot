extern crate sawtooth_sdk;

mod error;
mod handler;

pub use error::*;

use handler::CbTransactionHandler;
use sawtooth_sdk::processor::TransactionProcessor;

fn main() {
    let endpoint = "tcp://localhost:4004";

    let handler = CbTransactionHandler::new();
    let mut processor = TransactionProcessor::new(endpoint);

    processor.add_handler(&handler);
    processor.start();
}
