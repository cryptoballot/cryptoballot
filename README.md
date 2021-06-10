CryptoBallot
============

[![docs](https://docs.rs/cryptoballot/badge.svg)](https://docs.rs/cryptoballot)
[![crates.io](https://meritbadge.herokuapp.com/cryptoballot)](https://crates.io/crates/cryptoballot)
[![checks](https://github.com/cryptoballot/cryptoballot/workflows/checks/badge.svg)](https://github.com/cryptoballot/cryptoballot/actions)
[![codecov](https://codecov.io/gh/cryptoballot/cryptoballot/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptoballot/cryptoballot)


CryptoBallot is a cryptographically secure decentralized end-to-end verifiable voting system meant for real-world elections. It is a "backend" service providing vote storage, cryptographic operations, and an API. It does not provide a user interface - although it is built to make creating a UI that interfaces with it easy.

It uses  Shamir Secret Sharing for election decryption keys, blind-signing for voter anonymity, and an optional blockchain backend for distributed transaction storage and verification.  It supports all tally methods including write-in candidates. 

## Goals

1. **Verifiable** - the entire voting process should be end-to-end verifiable.
2. **Ergonomic** - Easy to use.
3. **Fast** - 1,000 votes per second
4. **Scalable** - Millions of voters.
5. **Secure** - Rock solid security guarantees, byzantine fault tolerance. 

## Current State

Under active development. Not ready for production use!  

## Road Map

| Status¹ | Feature                           | Notes                                                          |
| ------- | --------------------------------------- | -------------------------------------------------------------- |
| ✓       | Migrate from Go to Rust                 | 🦀                                                             |
| ✓       | Blind-Signing (RSA)                     | Uses [RSA-FDH](https://github.com/phayes/rsa-fdh)              |
|         | Blind-Signing (ed25519 / schnorr)       | Will replace current RSA bling-signing                         |
| ✓       | Distributed key generation / decryption | Uses [cryptid](https://github.com/eleanor-em/cryptid/).        |
| ✓       | Optional Blockchain backend             | Uses [Exonum](https://exonum.com/) |
| ⚠       | Support all tally methods               | Uses [Tallystick](https://github.com/phayes/tallystick)        |
| ⚠       | REST frontend                           |                                                                |
|         | Onion mixnet (likely Sphinx)            | Strengthened voter anonymity - Depends on REST frontend        |
| ⚠       | Re-encryption mixnet                    | Provides coercion resistance. Will use [cryptid](https://github.com/eleanor-em/cryptid/).|
|         | Optional TiKV Backend                   | High performance (non-blockchain) backend                      |
| ⚠       | End-User Device Verification            | Uses [Benaoh Challenge](https://github.com/phayes/benaloh-challenge)|

1. ✓ means done, ⚠ means in-progress, blank means not started but support is planned.

## Quick Start

```bash
# Clone the repository
git clone git@github.com:cryptoballot/cryptoballot.git && cd cryptoballot

# Install the server and command-line tools (go make some tea, this will take a while)
cargo install --force --path=cryptoballot_cli
cargo install --force --path=cryptoballot_server

# Make a directory to hold our cryptoballot database
mkdir ~/.cryptoballot

# Start the server in dev-mode
# Make note of the printed CRYPTOBALLOT_SECRET_KEY (we will refer to this as <secret_key>)
cryptoballot_server run-dev --blockchain-path=~/.cryptoballot

# Example Output:
#   > Starting in development mode
#   CRYPTOBALLOT_SECRET_KEY=ddcd9d786ba3975f1c4ba215226f632c455cdd4de51d2183bc985f20f7abc3c9
#   > Starting cryptoballot server, listening on port 8080

# In another window, generate an election-transaction using the secret key from before
# This election is very basic with a single trustee, no authentication, and a single write-in-only plurality ballot-type
# Optionally visit http://localhost:8080/api/services/cryptoballot/transactions to see transactions
CRYPTOBALLOT_SECRET_KEY=<secret_key> cryptoballot election generate --post

# Make note of the generated election ID (we will refer to this as <election-id>)

# Create some votes
cryptoballot vote generate <election-id> "BARAK OBAMA" --post
cryptoballot vote generate <election-id> "SANTA CLAUSE" --post
cryptoballot vote generate <election-id> "BARAK OBAMA" --post
cryptoballot vote generate <election-id> "BARAK OBAMA" --post

# As the election-authority, you decide when the voting is over and votes should be mixed and decrypted
# This can be automated by setting an end-time in the election transaction
CRYPTOBALLOT_SECRET_KEY=<secret_key> cryptoballot voting_end generate <election-id> --post

# After the voting is over, the server will automatically mix and decrypt the votes
# Optionally visit http://localhost:8080/api/services/cryptoballot/transactions to see transactions

# Do an verifiable end-to-end verification of the election and get the results!
cryptoballot e2e <election-id> --print-tally --print-results

```

## Components

### [Core library](https://github.com/cryptoballot/cryptoballot/tree/master/cryptoballot)

1. Add `cryptoballot = "0.3.1"` to your [rust](https://www.rust-lang.org) project's `Cargo.toml` file. 

### [Command-line tool](https://github.com/cryptoballot/cryptoballot/tree/master/cryptoballot_cli)

1. Install [Rust](https://www.rust-lang.org), [ZeroMQ](https://zeromq.org/download), and [Protoc](http://google.github.io/proto-lens/installing-protoc.html)
2. Run `cargo install --path=cryptoballot_cli`

### [Sawtooth Transaction Processor](https://github.com/cryptoballot/cryptoballot/tree/master/cryptoballot_sawtooth_tp)

1. Install [Rust](https://www.rust-lang.org), [ZeroMQ](https://zeromq.org/download), and [Protoc](http://google.github.io/proto-lens/installing-protoc.html)
2. Install [Sawtooth](https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/installing_sawtooth.html)
3. Run `cargo install --path=cryptoballot_sawtooth_tp`
