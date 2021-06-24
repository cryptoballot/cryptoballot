CryptoBallot
============

[![docs](https://docs.rs/cryptoballot/badge.svg)](https://cryptoballot.com/doc/cryptoballot/index.html)
[![crates.io](https://meritbadge.herokuapp.com/cryptoballot)](https://crates.io/crates/cryptoballot)
[![checks](https://github.com/cryptoballot/cryptoballot/workflows/checks/badge.svg)](https://github.com/cryptoballot/cryptoballot/actions)


CryptoBallot is a cryptographically secure decentralized end-to-end verifiable voting system meant for real-world elections. It is a "backend" service providing vote storage, cryptographic operations, and an API. It does not provide a user interface - although it is built to make creating a UI that interfaces with it easy.

It uses distributed key-generation for election encryption keys, blind-signing and an elGamal re-encryption mixnet for voter anonymity, and an optional blockchain backend for distributed transaction storage and verification.  It supports all tally methods including write-in candidates. 

## Goals

1. **Verifiable** - the entire voting process should be end-to-end verifiable.
2. **Ergonomic** - Easy to use.
3. **Fast** - 5,000 votes per second for a single shard. 
4. **Scalable** - Billions of voters. Unlimited votes per second with horizontal shard scaling.
5. **Secure** - Rock solid security guarantees, byzantine fault tolerance. 
6. **Distributed** - Trust and redundency is distributed amongst an operator-selected set of trustees.

## Current State

Under active development. Not ready for production use!  

## Road Map

| Status¹ | Feature                           | Notes                                                          |
| ------- | --------------------------------------- | -------------------------------------------------------------- |
| ✓       | Migrate from Go to Rust                 | 🦀                                                             |
| ✓       | Distributed key generation / decryption | Uses [cryptid](https://github.com/eleanor-em/cryptid/).        |
| ✓       | Blind-Signing (RSA)                     | Uses [RSA-FDH](https://github.com/phayes/rsa-fdh)              |
|         | Blind-Signing ([schnorr](https://www.math.uni-frankfurt.de/~dmst/teaching/WS2013/Vorlesung/Pointcheval,Stern.pdf))       | Will replace current RSA blind-signing                         |
| ✓       | Re-encryption mixnet                    | Provides coercion resistant anonymity. Uses [cryptid](https://github.com/eleanor-em/cryptid/).|
| ✓       | Optional Blockchain backend             | Uses [Exonum](https://exonum.com/) |
| ⚠       | Support all tally methods               | Uses [Tallystick](https://github.com/phayes/tallystick)        |
| ⚠       | REST frontend                           |                                                                |
| ⚠       | End-User Device Verification            | Uses [Benaoh Challenge](https://github.com/phayes/benaloh-challenge)|
|         | TypeScript / JS Client Library          |                                                                |
|         | Dart Client Library (Android)           |                                                                |
|         | Swift Client Library (iOS)              |                                                                |

1. ✓ means done, ⚠ means in-progress, blank means not started but support is planned.

## Quick Start

```bash

# Install dependencies (Mac)
brew install jq pkg-config protobuf

# Install dependencies (Debian / Ubuntu)
sudo apt-get install build-essential jq libsnappy-dev libssl-dev \
pkg-config clang-7 lldb-7 lld-7 protobuf-compiler libprotobuf-dev

# Clone the repository
git clone git@github.com:cryptoballot/cryptoballot.git && cd cryptoballot

# Install the server and command-line tools (go make some tea, this will take a while)
cargo install --force --path=cryptoballot_server
cargo install --force --path=cryptoballot_cli

# Make a directory to hold our cryptoballot database
mkdir $HOME/.cryptoballot

# Start the server in development mode (dev-mode will autogenerate and print the private-key). 
# Make note of the printed CRYPTOBALLOT_SECRET_KEY. We will refer to this as <secret_key>.
# WARNING: Don't use `run-dev` for production.
cryptoballot_server run-dev --blockchain-path=$HOME/.cryptoballot

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
cryptoballot vote generate <election-id> "EASTER BUNNY" --post
cryptoballot vote generate <election-id> "SANTA CLAUSE" --post
cryptoballot vote generate <election-id> "EASTER BUNNY" --post
cryptoballot vote generate <election-id> "SANTA CLAUSE" --post
cryptoballot vote generate <election-id> "SANTA CLAUSE" --post

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

1. Install [Rust](https://www.rust-lang.org), 
2. Run `cargo install --path=cryptoballot_cli`


### [Cryptoballot Server](https://github.com/cryptoballot/cryptoballot/tree/master/cryptoballot_server)

1. Install [Rust](https://www.rust-lang.org), 
2. Install dependencies (see below)
3. Run `cargo install --path=cryptoballot_cli`

#### Dependencies

Cryptoballot Server depends on the following third-party system libraries:
 - RocksDB (storage engine)
 - libsodium (cryptography engine)
 - Protocol Buffers (mechanism for serializing structured data)

Other components (core library, command-line tools) don't require these dependencies.

**Mac**

```bash
brew install jq pkg-config protobuf
```

**Debian / Ubuntu**

```bash
sudo apt-get install build-essential jq libsnappy-dev libssl-dev \
pkg-config clang-7 lldb-7 lld-7 protobuf-compiler libprotobuf-dev
```


## Related papers

These papers will help in understanding the underlying theory and mathematical foundations involved in CryptoBallot:
1. [Verifiable Vote-by-mail](https://www.eleanorve.net/static/thesis.pdf), *Eleanor McMurtry*
2. [A Threshold Cryptosystem
without a Trusted Party](https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf), *Pederson*
3. [Pseudo-Code Algorithms for Verifiable
Re-Encryption Mix-Nets](https://fc17.ifca.ai/voting/papers/voting17_HLKD17.pdf), *Haenni et al.*
4. [Exonum: Byzantine fault tolerant protocol](https://bitfury.com/content/downloads/wp_consensus_181227.pdf), *Yanovich et al.*
