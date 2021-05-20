use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use std::env::var;

pub struct Config {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub authority_public_key: PublicKey,
    pub db_path: String,
}

impl Config {
    pub fn from_env() -> Self {
        let secret_key = match var("CRYPTOBALLOT_SECRET_KEY") {
            Ok(val) => {
                let bytes = hex::decode(val).unwrap();
                SecretKey::from_bytes(&bytes).unwrap()
            }
            Err(_e) => {
                panic!("CRYPTOBALLOT_SECRET_KEY environment variable must be set")
            }
        };

        let public_key = (&secret_key).into();

        let authority_public_key: PublicKey = match var("CRYPTOBALLOT_AUTHORITY_PUBLIC_KEY") {
            Ok(val) => {
                let bytes = hex::decode(val).unwrap();
                PublicKey::from_bytes(&bytes).unwrap()
            }
            Err(_e) => {
                // Assume that WE are the authority
                (&secret_key).into()
            }
        };

        let db_path: String = match var("CRYPTOBALLOT_DB_PATH") {
            Ok(val) => val,
            Err(_e) => "./cryptoballot.db".to_owned(),
        };

        Config {
            secret_key,
            public_key,
            authority_public_key,
            db_path,
        }
    }
}
