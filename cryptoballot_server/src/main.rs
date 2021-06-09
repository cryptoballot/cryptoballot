#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

pub mod api;
pub mod service;
pub mod tasks;

use ed25519_dalek::{PublicKey, SecretKey};
use exonum_cli::{NodeBuilder, Spec};
use std::sync::{Arc, RwLock};

lazy_static! {
    pub static ref SERVICE_SECRET: Arc<RwLock<Option<SecretKey>>> = Arc::new(RwLock::new(None));
}

pub fn secret_key() -> SecretKey {
    let secret = SERVICE_SECRET.read().unwrap();
    let secret = secret.as_ref().unwrap();
    SecretKey::from_bytes(secret.as_ref()).unwrap()
}

pub fn public_key() -> PublicKey {
    let secret = SERVICE_SECRET.read().unwrap();
    let secret: &SecretKey = secret.as_ref().unwrap();
    let public: PublicKey = (secret).into();
    public
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    exonum::helpers::init_logger().unwrap();
    let builder =
        NodeBuilder::new().with(Spec::new(service::CryptoballotService).with_default_instance());

    if let Some(node) = builder.execute_command()? {
        // Store the secret-key so we can access it from other contexts
        let keypair = node.blockchain().service_keypair();
        let secret_key = hex::decode(keypair.secret_key().to_hex()).unwrap();
        let secret_key = SecretKey::from_bytes(&secret_key[..32]).unwrap();
        {
            let mut sk = SERVICE_SECRET.write().unwrap();
            *sk = Some(secret_key)
        }

        // Run the node
        return node.run().await;
    }

    Ok(())
}
