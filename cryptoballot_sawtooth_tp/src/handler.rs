use cryptoballot::*;
use digest::Digest;
use lazy_static::lazy_static;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use sha2::Sha512;
use std::convert::Into;

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

        let transaction: SignedTransaction = serde_cbor::from_slice(&request.payload).unwrap();
        let state = CbState::new(context);

        match &transaction {
            SignedTransaction::Election(signed) => {
                // TODO: check election authority stored in sawset settings
                signed.verify_signature().unwrap();
                signed.validate().unwrap();
            }

            SignedTransaction::Vote(vote) => {
                let election: Signed<ElectionTransaction> = state.get_inner(vote.election).unwrap();

                vote.verify_signature().unwrap();
                vote.validate(&election).unwrap();
            }

            SignedTransaction::SecretShare(secret_share) => {
                let election: Signed<ElectionTransaction> =
                    state.get_inner(secret_share.election).unwrap();

                secret_share.verify_signature().unwrap();
                secret_share.validate(&election).unwrap();
            }

            SignedTransaction::Decryption(decryption) => {
                decryption.verify_signature().unwrap();

                let election: Signed<ElectionTransaction> =
                    state.get_inner(decryption.election).unwrap();

                let vote: Signed<VoteTransaction> = state.get_inner(decryption.vote).unwrap();

                let mut secret_shares =
                    Vec::<SecretShareTransaction>::with_capacity(election.trustees.len());
                for trustee in election.trustees.iter() {
                    let secret_share_id =
                        SecretShareTransaction::build_id(decryption.election, trustee.id);

                    let secret_share: Signed<SecretShareTransaction> =
                        state.get_inner(secret_share_id).unwrap();
                    secret_shares.push(secret_share.inner().to_owned());
                }

                decryption.verify_signature().unwrap();
                decryption
                    .validate(&election, &vote, &secret_shares)
                    .unwrap();
            }
        }

        // Validation passed
        state.set(&transaction)
    }
}

// Get the full address prefix for the given transaction
fn cb_address(transaction_id: &Identifier) -> String {
    format!("{}{}", CB_PREFIX.as_str(), transaction_id.to_string())
}

// Get the address prefix for the given type
// Querying by this address will return all transactions of this type for this election.
fn cb_address_type(election_id: &Identifier, tx_type: TransactionType) -> String {
    let mut ident = election_id.clone();
    ident.transaction_type = tx_type;
    let address = ident.to_string();
    format!("{}{}", CB_PREFIX.as_str(), &address[0..16])
}

pub struct CbState<'a> {
    context: &'a mut dyn TransactionContext,
}

impl<'a> CbState<'a> {
    pub fn new(context: &'a mut dyn TransactionContext) -> CbState {
        CbState { context }
    }

    pub fn get(&self, transaction_id: Identifier) -> Result<Option<SignedTransaction>, ApplyError> {
        let address = cb_address(&transaction_id);
        let d = self.context.get_state_entry(&address)?;
        match d {
            Some(packed) => match SignedTransaction::from_bytes(&packed) {
                Ok(t) => return Ok(Some(t)),
                Err(e) => Err(ApplyError::InternalError(format!(
                    "Unable to parse transaction {}: {}",
                    transaction_id.to_string(),
                    e
                ))),
            },
            None => Ok(None),
        }
    }

    pub fn get_inner<T: From<SignedTransaction>>(
        &self,
        transaction_id: Identifier,
    ) -> Result<T, ()> {
        let tx: T = self.get(transaction_id).unwrap().unwrap().into();
        Ok(tx)
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
