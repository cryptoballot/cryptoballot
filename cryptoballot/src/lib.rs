#[macro_use]
extern crate serde;

use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;

mod authn;
mod decryption;
mod election;
mod util;
mod vote;

pub use authn::*;
pub use decryption::*;
pub use election::*;
pub use util::*;
pub use vote::*;

pub struct SignedTransaction<T> {
    pub transaction: T,
    pub signature: Signature,
}

pub struct KeyGenerationTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub trustee: uuid::Uuid,
    pub shared: Vec<u8>,
    pub signature: Option<Signature>,
}

pub struct ElectionKeyTransaction {
    pub election_key: PublicKey,
}

pub struct ReEncryptionTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub vote: uuid::Uuid,
    pub previous_reencryption: Option<uuid::Uuid>,
    pub reencrypted: Vec<u8>,
}

pub struct VoteDecryptionTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub voter_public_key: PublicKey,
}

pub struct ElectionTallyTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
}

#[cfg(test)]
mod tests;
