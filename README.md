CryptoBallot
============

CryptoBallot is a cryptographically secure decentralized E2E voting protocol meant for real-world elections.

It is written in the Rust programming language.


Features
--------
 - All votes are anoymous.
 - All voters can verify that their vote has been counted.
 - All voters can verify that all the votes have been tallied correctly.


Design
-------
 - Shamir secret sharing for election decryption keys
 - A re-encryption mixnet for vote anonimity
 - Supports all tally methods including write-in candidates
 - An optional blockchain backend for distriuted transaction storage and verification.

