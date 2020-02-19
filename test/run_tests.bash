# Election 1
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_1.election.json
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_1.election.json
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_2.vote.json
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_3.secret_share.json
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_4.secret_share.json
cargo run --bin="cryptoballot_cli" -- post test_election_1/transaction_5.decryption.json