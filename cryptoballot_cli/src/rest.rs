pub use super::*;
use cryptoballot;
use cryptoballot::SignedTransaction;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StateResp {
    data: String, // base-64
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StateRespList {
    data: Vec<StateResp>,
}

pub fn send_batch_list(batch_list_bytes: Vec<u8>, uri: &str) -> Result<(), reqwest::Error> {
    let full_uri = format!("{}/batches", uri);
    let client = reqwest::blocking::Client::new();
    client
        .post(&full_uri)
        .header("Content-Type", "application/octet-stream")
        .body(batch_list_bytes)
        .send()?;

    Ok(())
}

pub fn get_transaction(
    id: cryptoballot::Identifier,
    uri: &str,
) -> Result<SignedTransaction, reqwest::Error> {
    let address = identifier_to_address(id);
    let full_uri = format!("{}/state/{}", uri, address);
    let client = reqwest::blocking::Client::new();
    let res: StateResp = client.get(&full_uri).send()?.json()?;

    // TODO: Remove these unwrap
    let bytes = base64::decode(&res.data.as_bytes()).unwrap();
    let tx = cryptoballot::SignedTransaction::from_bytes(&bytes).unwrap();

    Ok(tx)
}

pub fn get_multiple_transactions(
    election_id: cryptoballot::Identifier,
    tx_type: Option<cryptoballot::TransactionType>,
    uri: &str,
) -> Result<Vec<SignedTransaction>, reqwest::Error> {
    let address = identifier_to_address_prefix(election_id, tx_type);

    let full_uri = format!("{}/state?address={}", uri, address);
    let client = reqwest::blocking::Client::new();
    let res: StateRespList = client.get(&full_uri).send()?.json()?;

    let mut txs = Vec::<SignedTransaction>::with_capacity(res.data.len());

    for state_resp in res.data {
        let bytes = base64::decode(&state_resp.data.as_bytes()).unwrap();
        let tx = cryptoballot::SignedTransaction::from_bytes(&bytes).unwrap();
        txs.push(tx);
    }

    Ok(txs)
}
