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
        hex::encode(&sha.result()[..6])
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

        let transaction: SignedTransaction = serde_json::from_slice(&request.payload).unwrap();
        let state = CbState::new(context);

        match &transaction {
            SignedTransaction::Election(signed) => {
                // TODO: check election authority stored in sawset settings
                signed.verify_signature().unwrap();
                signed.inner().validate().unwrap();
            }

            SignedTransaction::Vote(signed) => {
                let election: Signed<ElectionTransaction> =
                    state.get_inner(signed.tx.election).unwrap();

                signed.verify_signature().unwrap();
                signed.inner().validate(election.inner()).unwrap();
            }

            SignedTransaction::SecretShare(signed) => {
                let election: Signed<ElectionTransaction> =
                    state.get_inner(signed.tx.election).unwrap();

                signed.verify_signature().unwrap();
                signed.inner().validate(election.inner()).unwrap();
            }

            SignedTransaction::Decryption(signed) => {
                signed.verify_signature().unwrap();
                let decrypt = signed.inner();

                let election: Signed<ElectionTransaction> =
                    state.get_inner(decrypt.election).unwrap();

                let vote: Signed<VoteTransaction> = state.get_inner(decrypt.vote).unwrap();

                let secret_shares: Vec<Signed<SecretShareTransaction>> = state
                    .get_all_type(decrypt.election, TransactionType::SecretShare)
                    .unwrap();

                let secret_shares: Vec<SecretShareTransaction> =
                    secret_shares.iter().map(|e| e.inner().to_owned()).collect();

                signed.verify_signature().unwrap();
                signed
                    .inner()
                    .validate(election.inner(), vote.inner(), &secret_shares)
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
            Some(packed) => match SignedTransaction::unpack(&packed) {
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

    pub fn get_all_type<T: From<SignedTransaction>>(
        &self,
        election_id: Identifier,
        tx_type: TransactionType,
    ) -> Result<Vec<T>, ApplyError> {
        let address_prefix = cb_address_type(&election_id, tx_type);
        let d = self.context.get_state_entries(&[address_prefix])?;

        // TODO: fix this unwrap
        let transactions = d
            .iter()
            .map(|e| SignedTransaction::unpack(&e.1).unwrap().into())
            .collect();
        Ok(transactions)
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
        let packed = transaction.pack();
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
