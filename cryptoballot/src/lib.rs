//! CryptoBallot is a cryptographically secure online voting system, providing secure anonymous voting with end-to-end verifiability.
//!
//! It is currenly under active development and is not production ready.
//!
//! CryptoBallot is fundamentally a transaction processor and validator. When transactions are validated in order, it creates an end-to-end verifiable voting system.
//!
//! ## Glossary:
//!  - **Transaction 1: Election Transaction** - Defines an election, created by an election authority.
//!  - **Transaction 2: Vote Transaction** - Posted by a voter to cast a vote in an election.
//!  - **Transaction 3: Secret Share Transaction** - Posted by a trustee to allow votes to be decrypted and viewed.
//!  - **Transaction 4: Decryption Transaction** - Decrypt a vote, allowing it to be tallied.
//!  - **Election Authority** - Creates an Election Transaction and distributes the encryption secret to trustees via Shamir Secret Sharing.
//!  - **Trustee** - Holds a vote-decryption secret share, posts Secret Share Transactions.
//!  - **Authenticator** - Certifies that a voter can vote an election and ballot using blind-signing.
//!  - **Ballot** - A set of contests for an election, usually restricted to a geographic area.

#![feature(is_sorted)]

#[macro_use]
extern crate serde;

pub extern crate cryptid;
pub extern crate uuid;

mod authn;
mod decryption;
mod election;
mod error;
mod keygen;
mod mix;
mod serde_hex;
mod store;
mod transaction;
mod trustee;
mod util;
mod vote;
mod voting_end;

pub use authn::*;
pub use decryption::*;
pub use election::*;
pub use error::*;
pub use keygen::*;
pub use mix::*;
pub use store::*;
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
