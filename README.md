CryptoBallot
============

CryptoBallot is a cryptographically secure decentralized E2E voting protocol meant for real-world elections.

It is written in the Rust programming language.


Features
--------
 - All votes are anonymous.
 - All voters can verify that their vote has been counted.
 - All voters can verify that all the votes have been tallied correctly.


Design
-------
 - Shamir secret sharing for election decryption keys
 - Various options for voter anonimity:
    - Blind Signing
    - Homomorphic Tally
    - Re-encryption mixnet (planned)
 - Supports all tally methods including write-in candidates
 - An optional blockchain backend for distriuted transaction storage and verification.
 - Ed25519 for all cryptographic operations.
