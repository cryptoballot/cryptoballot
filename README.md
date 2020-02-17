CryptoBallot
============

CryptoBallot is a cryptographically secure decentralized E2E voting system meant for real-world elections. It is a "backend" service providing vote storage, cryptographic operations, and an API. It does not provide a user interface.

It uses  Shamir Secret Sharing for election decryption keys, blind-signing for voter anonymity, and an optional blockchain backend for distributed transaction storage and verification.  It supports all tally methods including write-in candidates. 

## Goals

1. **Verifiable** - the entire voting process should be end-to-end verifiable.
2. **Ergonomic** - Easy to use.
3. **Fast** - 1,000 votes per second.
4. **Scalable** - Millions of voters.
5. **Secure** - Rock solid security guaruntees.

## Current State

Under active development. Not ready for production use!  

## Road Map

| Status¹ | Feature                           | Notes                                                          |
| ------- | --------------------------------- | -------------------------------------------------------------- |
| ✓       | Migrate from Go to Rust           | 🦀                                                             |
| ⚠       | Blind-Signing (RSA)               | Uses [RSA-FDH](https://github.com/phayes/rsa-fdh)              |
|         | Blind-Signing (ed25519)           | Will replace current RSA bling-signing                         |
| ✓       | Shamir Secret Sharing             | Uses [Sharks](https://docs.rs/sharks/)                         |
| ⚠       | Blockchain backend                | Uses [Hyperledger Sawtooth](https://sawtooth.hyperledger.org/) |
| ⚠       | Support all tally methods         | Uses [Tallystick](https://github.com/phayes/tallystick)        |
|         | REST frontend                     |                                                                |
|         | Distributed key generation        | Replace Shamir, uses ElGamal, fully verifiable and distributed |
|         | Onion mixnet (likely Sphinx)      | Strengthened voter anonymity - Depends on REST frontend        |
|         | Re-encryption mixnet              | Strengthened voter anonymity - far future if ever              |

1. ✓ means done, ⚠ means in-progress, blank means not started but support is planned.
