//! CryptoBallot is a cryptographically secure online voting system, providing secure anonimous voting with end-to-end verifiability.
//!
//! It is currenly under active development and is not production ready.
//!
//! CryptoBallot is fundementally a transaction processor and validator, that when taken together creates an end-to-end verifiable voting system.
//!
//! ## Glossary:
//!  - **Transaction 1: Election Transaction** - Defines an election, created by an election authority.
//!  - **Transaction 2: Vote Transaction** - Posted by a voter to cast a vote in an election.
//!  - **Transaction 3: Secret Share Transaction** - Posted by a trustee to allow votes to be decrypted and viewed.
//!  - **Transaction 4: Decryption Transaction** - Decrypt a vote, allowing it to be tallied.
//!  - **Election Authority** - Creates an Election Transaction and distributes encryption secret to trustees via Shamir Secret Sharing.
//!  - **Trustee** - Holds a vote decryption secret share, posts Secret Share Transactions.
//!  - **Authenticator** - Certified that a voter can vote an election and ballot using blind-singing.
//!  - **Ballot** - A set of contests for an election, usually restricted to a geographic area.

#[macro_use]
extern crate serde;

mod authn;
mod decryption;
mod election;
mod error;
mod secret_share;
mod serde_hex;
mod transaction;
mod util;
mod vote;

pub use authn::*;
pub use decryption::*;
pub use election::*;
pub use error::*;
pub use secret_share::*;
pub use transaction::*;
pub use util::*;
pub use vote::*;

pub(crate) use serde_hex::*;

#[cfg(test)]
mod tests;
