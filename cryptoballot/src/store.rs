use crate::*;
use failure::Fail;
use std::fmt::Display;

#[derive(Debug, Clone, Fail)]
pub struct TransactionNotFound(pub Identifier);

impl Display for TransactionNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "transaction {} not found", self.0)
    }
}

/// A transaction store
pub trait Store {
    /// Get a transaction of an unknown type
    fn get_transaction(&self, id: Identifier) -> Option<SignedTransaction>;

    // TODO: Macro these methods

    /// Get an election transaction
    fn get_election(
        &self,
        id: Identifier,
    ) -> Result<Signed<ElectionTransaction>, TransactionNotFound> {
        let tx = self.get_transaction(id);
        match tx {
            Some(tx) => match tx {
                SignedTransaction::Election(e) => Ok(e),
                _ => Err(TransactionNotFound(id)),
            },
            None => Err(TransactionNotFound(id)),
        }
    }

    /// Get an Vote transaction
    fn get_vote(&self, id: Identifier) -> Result<Signed<VoteTransaction>, TransactionNotFound> {
        let tx = self.get_transaction(id);
        match tx {
            Some(tx) => match tx {
                SignedTransaction::Vote(e) => Ok(e),
                _ => Err(TransactionNotFound(id)),
            },
            None => Err(TransactionNotFound(id)),
        }
    }

    /// Get a SecretShare transaction
    fn get_secret_share(
        &self,
        id: Identifier,
    ) -> Result<Signed<SecretShareTransaction>, TransactionNotFound> {
        let tx = self.get_transaction(id);
        match tx {
            Some(tx) => match tx {
                SignedTransaction::SecretShare(e) => Ok(e),
                _ => Err(TransactionNotFound(id)),
            },
            None => Err(TransactionNotFound(id)),
        }
    }

    /// Get a Decryption transaction
    fn get_decryption(
        &self,
        id: Identifier,
    ) -> Result<Signed<DecryptionTransaction>, TransactionNotFound> {
        let tx = self.get_transaction(id);
        match tx {
            Some(tx) => match tx {
                SignedTransaction::Decryption(e) => Ok(e),
                _ => Err(TransactionNotFound(id)),
            },
            None => Err(TransactionNotFound(id)),
        }
    }
}
