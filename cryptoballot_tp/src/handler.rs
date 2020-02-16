use cryptoballot::*;
use digest::Digest;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use sha2::Sha512;
use std::convert::Into;

pub fn get_cb_prefix() -> String {
    let mut sha = Sha512::new();
    sha.input("cryptoballot");
    hex::encode(&sha.result()[..6])
}

pub struct CbTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl CbTransactionHandler {
    pub fn new() -> CbTransactionHandler {
        CbTransactionHandler {
            family_name: String::from("cryptoballot"),
            family_versions: vec![String::from("1.0")],
            namespaces: vec![String::from(get_cb_prefix().to_string())],
        }
    }
}

impl TransactionHandler for CbTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut dyn TransactionContext,
    ) -> Result<(), ApplyError> {
        let header = &request.header;
        let signer = match &header.as_ref() {
            Some(s) => &s.signer_public_key,
            None => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid header",
                )))
            }
        };

        let transaction: Transaction = serde_json::from_slice(&request.payload).unwrap();
        let state = CbState::new(context);

        match &transaction {
            Transaction::Election(tx) => {
                tx.validate().unwrap();
            }
            Transaction::Vote(tx) => {
                let election: ElectionTransaction = state.get_inner(tx.election).unwrap();
                tx.validate(&election).unwrap();
            }
            Transaction::Decryption(tx) => {
                tx.validate().unwrap();
            }
        }

        // Validation passed
        state.set(&transaction)
    }
}

pub struct CbState<'a> {
    context: &'a mut dyn TransactionContext,
}

impl<'a> CbState<'a> {
    pub fn new(context: &'a mut dyn TransactionContext) -> CbState {
        CbState { context }
    }

    pub fn get(
        &self,
        transaction_id: TransactionIdentifier,
    ) -> Result<Option<Transaction>, ApplyError> {
        let transaction_id = transaction_id.to_string();
        let d = self.context.get_state_entry(&transaction_id)?;
        match d {
            Some(packed) => match Transaction::unpack(&packed) {
                Ok(t) => return Ok(Some(t)),
                Err(e) => Err(ApplyError::InternalError(format!(
                    "Unable to parse transaction {}: {}",
                    transaction_id, e
                ))),
            },
            None => Ok(None),
        }
    }

    pub fn get_inner<T: From<Transaction>>(
        &self,
        transaction_id: TransactionIdentifier,
    ) -> Result<T, ()> {
        let tx: T = self.get(transaction_id).unwrap().unwrap().into();
        Ok(tx)
    }

    pub fn set(&self, transaction: &Transaction) -> Result<(), ApplyError> {
        let transaction_id = transaction.id().to_string();
        let packed = transaction.pack();
        self.context
            .set_state_entry(transaction_id.clone(), packed)
            .map_err(|err| {
                ApplyError::InternalError(format!(
                    "Error storing transaction {}: {}",
                    transaction_id, err
                ))
            })?;
        Ok(())
    }
}
