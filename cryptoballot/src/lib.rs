//! CryptoBallot is a cryptographically secure online voting system, providing secure anonymous voting with end-to-end verifiability.
//!
//! It is currenly under active development and is not production ready.
//!
//! CryptoBallot is fundamentally a transaction processor and validator. When transactions are validated in order, it creates an end-to-end verifiable voting system.
//!
//! ## Glossary:
//!  - **Transaction 1: Election Transaction** - Defines an election, created by an election authority.
//!  - **Transaction 2: KeyGenCommitment Transaction** - Trustee commitment to participate in this election.
//!  - **Transaction 3: KeyGenShare Transaction** - Trustee Key Generation Share - needed to generate Election Encryption Key.
//!  - **Transaction 4: KeyGenPublicKey Transaction** - Trustee's computation of the Election Encryption Key.
//!  - **Transaction 5: EncryptionKey Transaction** - The Encryption Key that will be used by voters to encrypt their vote.
//!  - **Transaction 6: Vote Transaction** - Voter's encrypted vote.
//!  - **Transaction 7: VotingEnd Transaction** - Denotes the end of voting.
//!  - **Transaction 8: Mix Transaction** - Shuffled and mixed vote for a single contest, created by a trustee.
//!  - **Transaction 9: PartialDecryption Transaction** - A partially decrypted vote from a trustee.
//!  - **Transaction 10: Decryption Transaction** - A fully decrypted vote .
//!  - **Election Authority** - Creates an Election Transaction.
//!  - **Trustee** - A group of trustees collectively create the encryption-key, decrypt votes, and run the mixnet. Generally ⅔ of trustees are required to be honest for the CryptoBallot protocol to function.
//!  - **Authenticator** - Certifies that a voter can vote an election and ballot.
//!  - **Contest** - A single question that voters are voting on.
//!  - **Ballot** - A set of contests, usually restricted to a geographic area. A single contest can exist across multiple ballots.

#![feature(is_sorted)]

#[macro_use]
extern crate serde;

pub extern crate cryptid;
pub extern crate ed25519_dalek;
pub extern crate indexmap;
pub extern crate rand_core;
pub extern crate rsa;
pub extern crate uuid;
pub extern crate x25519_dalek;

mod authn;
mod ballot;
mod decryption;
mod election;
mod error;
mod keygen;
mod mix;
mod serde_hex;
mod store;
mod tally;
mod transaction;
mod trustee;
mod util;
mod vote;
mod voting_end;

pub use authn::*;
pub use ballot::*;
pub use decryption::*;
pub use election::*;
pub use error::*;
pub use keygen::*;
pub use mix::*;
pub use store::*;
pub use tally::*;
pub use transaction::*;
pub use trustee::*;
pub use util::*;
pub use vote::*;
pub use voting_end::*;

pub(crate) use serde_hex::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub use tests::*;
