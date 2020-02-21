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
| ------- | --------------------------------- | -------------------------------------------------------------- |
| ✓       | Migrate from Go to Rust           | 🦀                                                             |
| ✓       | Blind-Signing (RSA)               | Uses [RSA-FDH](https://github.com/phayes/rsa-fdh)              |
|         | Blind-Signing (ed25519)           | Will replace current RSA bling-signing                         |
| ✓       | Shamir Secret Sharing             | Uses [Sharks](https://docs.rs/sharks/)                         |
| ⚠       | Blockchain backend                | Uses [Hyperledger Sawtooth](https://sawtooth.hyperledger.org/) |
| ⚠       | Support all tally methods         | Uses [Tallystick](https://github.com/phayes/tallystick)        |
|         | REST frontend                     |                                                                |
|         | Distributed key generation        | Replace Shamir, uses ElGamal, fully verifiable and distributed |
|         | Onion mixnet (likely Sphinx)      | Strengthened voter anonymity - Depends on REST frontend        |
|         | Re-encryption mixnet              | Provides coercion resistance                                   |
| ⚠       | End-User Device Verification      | Uses [Benaoh Challenge](https://github.com/phayes/benaloh-challenge)|

1. ✓ means done, ⚠ means in-progress, blank means not started but support is planned.


## Components

### cryptoballot - Core library

**Location**: `./cryptoballot`

**Installation**

Add `cryptoballot = "0.3.1"` to your [rust](https://www.rust-lang.org) project's `Cargo.toml` file. 

### cryptoballot_cli - Command-line tool

**Location**: `./cryptoballot_cli`

**Installation**

1. Install [Rust](https://www.rust-lang.org), [ZeroMQ](https://zeromq.org/download), and [Protoc](http://google.github.io/proto-lens/installing-protoc.html)
2. Run `cargo install --path=cryptoballot_cli`

### cryptoballot_sawtooth_tp - Sawtooth Transaction Processor

**Location**: `./cryptoballot_sawtooth_tp`

**Installation**

1. Install [Rust](https://www.rust-lang.org), [ZeroMQ](https://zeromq.org/download), and [Protoc](http://google.github.io/proto-lens/installing-protoc.html)
2. Install [Sawtooth](https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/installing_sawtooth.html)
3. Run `cargo install --path=cryptoballot_sawtooth_tp`
