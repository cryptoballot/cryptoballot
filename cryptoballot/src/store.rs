use crate::*;
use failure::Fail;
use std::collections::BTreeMap;
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

/// A simple store that uses an in-memory BTreeMap
#[derive(Default, Clone)]
pub struct MemStore {
    inner: BTreeMap<String, SignedTransaction>,
}

impl MemStore {
    pub fn set(&mut self, tx: SignedTransaction) {
        self.inner.insert(tx.id().to_string(), tx);
    }

    pub fn get_multiple(
        &self,
        election_id: Identifier,
        tx_type: TransactionType,
    ) -> Vec<SignedTransaction> {
        let mut results = Vec::new();

        let mut start = election_id.clone();
        start.transaction_type = tx_type;
        let start = start.to_string();

        let mut end = start.clone();
        end.truncate(32);
        let end = format!("{:f<64}", end);

        // TODO: Go back to using array keys (faster)
        // OLD CODE For Array Keys:
        //let election_id = election_id.to_array();
        //let mut start: [u8; 32] = [0; 32];
        //start[..15].copy_from_slice(&election_id[..15]);
        //start[16] = tx_type as u8;

        // End at the next transaction type
        //let mut end: [u8; 32] = [0; 32];
        //end[..15].copy_from_slice(&election_id[..15]);
        //end[16] = (tx_type as u8) + 1;

        for (_, v) in self.inner.range(start..end) {
            results.push(v.clone())
        }
        results
    }
}

impl Store for MemStore {
    fn get_transaction(&self, id: Identifier) -> Option<SignedTransaction> {
        let key = id.to_string();
        self.inner.get(&key).cloned()
    }
}

impl From<Vec<SignedTransaction>> for MemStore {
    fn from(item: Vec<SignedTransaction>) -> Self {
        let mut memstore = MemStore::default();
        for tx in item {
            memstore.set(tx);
        }
        memstore
    }
}
