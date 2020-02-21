use crate::*;
use cryptoballot::*;
use digest::Digest;
use lazy_static::lazy_static;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use sha2::Sha512;
use std::string::ToString;

lazy_static! {
    static ref CB_PREFIX: String = {
        let mut sha = Sha512::new();
        sha.input("cryptoballot");
        hex::encode(&sha.result()[..3])
    };
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
            namespaces: vec![CB_PREFIX.clone()],
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
        let _signer = match &header.as_ref() {
            Some(s) => &s.signer_public_key,
            None => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid header",
                )))
            }
        };
        // TODO: validate _signer

        // Deserialize transaction
        let transaction: SignedTransaction =
            serde_cbor::from_slice(&request.payload).map_err(|e| {
                ApplyError::InvalidTransaction(format!("cannot parse transaction: {}", e))
            })?;

        // Load the state
        let state = CbState::new(context);

        // Validate the transaction
        validate_transaction(&transaction, &state).map_err(|e| {
            let err = format!(
                "error validating {} {}: {}",
                transaction.transaction_type(),
                transaction.id().to_string(),
                &e
            );

            // TODO: This doesn't account for state network errors (should be InternalError)
            // TODO: turn get_transaction into a Result and bubble error to here and check
            ApplyError::InvalidTransaction(err)
        })?;

        // Store the transaction
        state.set(&transaction).map_err(|e| {
            ApplyError::InternalError(format!(
                "cannot store transaction {} {}: {}",
                transaction.transaction_type(),
                transaction.id().to_string(),
                e
            ))
        })
    }
}

fn validate_transaction(transaction: &SignedTransaction, state: &CbState) -> Result<(), TPError> {
    if let SignedTransaction::Election(_election) = transaction {
        // TODO: check election authority public key against settings
        // TODO: Load special "election_index" state and check that election-nonce has not been used yet
    } else {
        // All transaction except elections are immutable
        // TODO: Allow resubmisson to pass if they are the same??
        if state.get_transaction(transaction.id()).is_some() {
            return Err(TPError::AlreadyExists(transaction.id().to_string()));
        }
    }

    // This will validate both the signature and the signed transaction
    transaction.validate(state)?;

    // All checks pass
    Ok(())
}

// Get the full address prefix for the given transaction
fn cb_address(transaction_id: &Identifier) -> String {
    format!("{}{}", CB_PREFIX.as_str(), transaction_id.to_string())
}

pub struct CbState<'a> {
    context: &'a mut dyn TransactionContext,
}

impl<'a> CbState<'a> {
    pub fn new(context: &'a mut dyn TransactionContext) -> CbState {
        CbState { context }
    }

    pub fn get(&self, transaction_id: Identifier) -> Result<Option<SignedTransaction>, TPError> {
        let address = cb_address(&transaction_id);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => match SignedTransaction::from_bytes(&packed) {
                Ok(t) => return Ok(Some(t)),
                Err(_e) => Err(TPError::CannotParseTransaction(transaction_id.to_string())),
            },
            None => Ok(None),
        }
    }

    pub fn set(&self, transaction: &SignedTransaction) -> Result<(), ApplyError> {
        let address = cb_address(&transaction.id());
        let packed = transaction.as_bytes();
        self.context
            .set_state_entry(address, packed)
            .map_err(|err| {
                ApplyError::InternalError(format!(
                    "Error storing transaction {}: {}",
                    transaction.id().to_string(),
                    err
                ))
            })?;
        Ok(())
    }
}

impl<'a> Store for CbState<'a> {
    // TODO: Perhaps change this from Option<T> to Result<T>
    fn get_transaction(&self, id: Identifier) -> Option<SignedTransaction> {
        self.get(id).ok().flatten()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_address_translation() {
        let identifier = cryptoballot::Identifier::new_for_election();
        let address = cb_address(&identifier);

        assert!(address.len() == 70);
    }
}
