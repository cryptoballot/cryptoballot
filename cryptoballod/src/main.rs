use cryptoballot::*;
use db::Db;
use futures::future::TryFutureExt;
use futures::stream::TryStreamExt;
use rocket::response::status::Created;
use rocket::{futures, State};
use rocket_contrib::json::Json;
use std::sync::{Arc, Mutex};

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate lazy_static;

// global store to use as a fast-cache.  We can do this because transactions are immutable
lazy_static! {
    pub static ref MEM_STORE: Arc<Mutex<MemStore>> = Arc::new(Mutex::new(MemStore::default()));
}

mod db;

#[post("/api/tx", data = "<tx>")]
async fn create(
    db: &State<Db>,
    tx: Json<SignedTransaction>,
) -> db::Result<Created<Json<SignedTransaction>>> {
    tx.0.verify_signature().unwrap();
    {
        let mux_store = MEM_STORE.lock().unwrap();
        let store = &*mux_store;
        tx.validate(store).unwrap();
    }

    let serialized = serde_json::to_string_pretty(&tx.0).unwrap();
    let id = tx.id().to_string();
    let election_id = tx.id().election_id_string();
    let tx_type = tx.transaction_type().name().to_owned();
    sqlx::query!(
        "INSERT INTO tx (id, election_id, tx_type, tx_value) VALUES (?, ?, ?, ?)",
        id,
        election_id,
        tx_type,
        serialized
    )
    .execute(&**db)
    .await?;

    {
        let mut store = MEM_STORE.lock().unwrap();
        store.set(tx.0.clone());
    }

    Ok(Created::new("/").body(tx))
}

#[get("/api/tx/<id>")]
async fn read_tx(db: &State<Db>, id: String) -> Option<Json<SignedTransaction>> {
    sqlx::query!("SELECT tx_value FROM tx WHERE id = ?", id)
        .fetch_one(&**db)
        .map_ok(|r| {
            let tx = serde_json::from_str(&r.tx_value).unwrap();
            Json(tx)
        })
        .await
        .ok()
}

#[get("/api/election/<id>")]
async fn read_election(db: &State<Db>, id: String) -> Option<Json<SignedTransaction>> {
    let election_id = &id[..30];

    sqlx::query!(
        "SELECT tx_value FROM tx WHERE election_id = ? AND tx_type = 'election'",
        election_id
    )
    .fetch_one(&**db)
    .map_ok(|r| {
        let tx = serde_json::from_str(&r.tx_value).unwrap();
        Json(tx)
    })
    .await
    .ok()
}

#[get("/api/election/<id>/all")]
async fn read_election_tx_all(db: &State<Db>, id: String) -> Json<Vec<SignedTransaction>> {
    let election_id = &id[..30];

    let records = sqlx::query!(
        "SELECT tx_value FROM tx WHERE election_id = ? ORDER BY id",
        election_id,
    )
    .fetch(&**db)
    .map_ok(|r| serde_json::from_str(&r.tx_value).unwrap())
    .try_collect::<Vec<_>>()
    .await
    .unwrap();

    Json(records)
}

#[get("/api/election/<id>/<tx_type>")]
async fn read_election_tx_by_type(
    db: &State<Db>,
    id: String,
    tx_type: String,
) -> Json<Vec<SignedTransaction>> {
    let election_id = &id[..30];

    let records = sqlx::query!(
        "SELECT tx_value FROM tx WHERE election_id = ? AND tx_type = ? ORDER BY id",
        election_id,
        tx_type
    )
    .fetch(&**db)
    .map_ok(|r| serde_json::from_str(&r.tx_value).unwrap())
    .try_collect::<Vec<_>>()
    .await
    .unwrap();

    Json(records)
}

#[launch]
fn rocket() -> _ {
    rocket::build().attach(db::stage()).mount(
        "/",
        routes![
            create,
            read_tx,
            read_election,
            read_election_tx_all,
            read_election_tx_by_type
        ],
    )
}
