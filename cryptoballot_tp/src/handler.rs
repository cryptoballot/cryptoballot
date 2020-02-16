use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;

pub fn get_cb_prefix() -> String {
    let mut sha = Sha512::new();
    sha.input_str("cryptoballot");
    sha.result_str()[..6].to_string()
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

impl TransactionHandler for XoTransactionHandler {
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
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        
    }
}

fn apply(
    &self,
    request: &TpProcessRequest,
    context: &mut TransactionContext,
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

    let payload = XoPayload::new(&request.payload)?;

    let mut state = XoState::new(context);

    let game = state.get_game(payload.get_name().as_str())?;

    match payload.get_action().as_str() {
        "delete" => {
            // --snip--
        }
        "create" => {
            // --snip--
        }
        "take" => {
            // --snip--
            }
    }
}