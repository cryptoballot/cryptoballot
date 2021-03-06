pub use super::*;
use cryptoballot;
use cryptoballot::SignedTransaction;
use cryptoballot_exonum::Transaction;
use ed25519_dalek::SecretKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StateResp {
    data: String, // base-64
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StateRespList {
    data: Vec<StateResp>,
}

pub fn post_transaction(
    base_uri: &str,
    tx: SignedTransaction,
    _secret_key: Option<&SecretKey>,
) -> String {
    eprintln!(
        "> Posting {} transaction {} to {}",
        tx.transaction_type(),
        tx.id(),
        base_uri
    );

    let exonum_tx: Transaction = tx.into();

    // TODO: Use real keys
    let (public_key, sercet_key) = exonum_crypto::gen_keypair();
    let transaction_hex = exonum_tx.into_transaction_hex(public_key, &sercet_key);

    let client = reqwest::blocking::Client::new();
    let full_url = format!("{}/api/explorer/v1/transactions", base_uri);

    let res = client
        .post(&full_url)
        .json(&transaction_hex)
        .send()
        .unwrap();

    let res = res.text().unwrap();

    res
}

pub fn get_transaction(
    base_uri: &str,
    id: cryptoballot::Identifier,
) -> Result<SignedTransaction, reqwest::Error> {
    let full_uri = format!(
        "{}/api/services/cryptoballot/transaction?id={}",
        base_uri, id
    );
    let client = reqwest::blocking::Client::new();
    let res: SignedTransaction = client.get(&full_uri).send()?.json()?;

    Ok(res)
}

pub fn get_transactions_by_prefix(
    base_uri: &str,
    prefix: &str,
) -> Result<Vec<SignedTransaction>, reqwest::Error> {
    let full_uri = format!(
        "{}/api/services/cryptoballot/transactions?prefix={}",
        base_uri, prefix
    );
    let client = reqwest::blocking::Client::new();
    let res: Vec<SignedTransaction> = client.get(&full_uri).send()?.json()?;

    Ok(res)
}
