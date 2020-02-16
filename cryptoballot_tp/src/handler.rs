use cryptoballot::*;
use digest::Digest;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;
use sha2::Sha512;
use std::collections::HashMap;

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
}

pub struct CbState<'a> {
    context: &'a mut dyn TransactionContext,
    address_map: HashMap<String, Option<String>>,
}

impl<'a> CbState<'a> {
    pub fn new(context: &'a mut dyn TransactionContext) -> CbState {
        CbState {
            context,
            address_map: HashMap::new(),
        }
    }

    fn calculate_address(name: &str) -> String {
        let mut sha = Sha512::new();
        sha.input_str(name);
        get_xo_prefix() + &sha.result_str()[..64].to_string()
    }

    pub fn delete_game(&mut self, game_name: &str) -> Result<(), ApplyError> {
        let mut games = self._load_games(game_name)?;
        games.remove(game_name);
        if games.is_empty() {
            self._delete_game(game_name)?;
        } else {
            self._store_game(game_name, games)?;
        }
        Ok(())
    }

    pub fn set_game(&mut self, game_name: &str, g: Game) -> Result<(), ApplyError> {
        let mut games = self._load_games(game_name)?;
        games.insert(game_name.to_string(), g);
        self._store_game(game_name, games)?;
        Ok(())
    }

    pub fn get_game(&mut self, game_name: &str) -> Result<Option<Game>, ApplyError> {
        let games = self._load_games(game_name)?;
        if games.contains_key(game_name) {
            Ok(Some(games[game_name].clone()))
        } else {
            Ok(None)
        }
    }

    fn _store_game(
        &mut self,
        game_name: &str,
        games: HashMap<String, Game>,
    ) -> Result<(), ApplyError> {
        let address = XoState::calculate_address(game_name);
        let state_string = Game::serialize_games(games);
        self.address_map
            .insert(address.clone(), Some(state_string.clone()));
        self.context
            .set_state_entry(address, state_string.into_bytes())?;
        Ok(())
    }

    fn _delete_game(&mut self, game_name: &str) -> Result<(), ApplyError> {
        let address = XoState::calculate_address(game_name);
        if self.address_map.contains_key(&address) {
            self.address_map.insert(address.clone(), None);
        }
        self.context.delete_state_entry(&address)?;
        Ok(())
    }

    fn _load_games(&mut self, game_name: &str) -> Result<HashMap<String, Game>, ApplyError> {
        let address = XoState::calculate_address(game_name);

        Ok(match self.address_map.entry(address.clone()) {
            Entry::Occupied(entry) => match entry.get() {
                Some(addr) => Game::deserialize_games(addr).ok_or_else(|| {
                    ApplyError::InvalidTransaction("Invalid serialization of game state".into())
                })?,
                None => HashMap::new(),
            },
            Entry::Vacant(entry) => match self.context.get_state_entry(&address)? {
                Some(state_bytes) => {
                    let state_string = from_utf8(&state_bytes).map_err(|e| {
                        ApplyError::InvalidTransaction(format!(
                            "Invalid serialization of game state: {}",
                            e
                        ))
                    })?;

                    entry.insert(Some(state_string.to_string()));

                    Game::deserialize_games(state_string).ok_or_else(|| {
                        ApplyError::InvalidTransaction("Invalid serialization of game state".into())
                    })?
                }
                None => {
                    entry.insert(None);
                    HashMap::new()
                }
            },
        })
    }
}
