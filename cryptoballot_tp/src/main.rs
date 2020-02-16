extern crate sawtooth_sdk;

mod handler;

use handler::XoTransactionHandler;
use sawtooth_sdk::processor::TransactionProcessor;

fn main() {
    let endpoint = "tcp://localhost:4004";

    let handler = XoTransactionHandler::new();
    let mut processor = TransactionProcessor::new(endpoint);

    processor.add_handler(&handler);
    processor.start();
}
