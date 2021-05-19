use rocket::fairing::{self, AdHoc};
use rocket::{Build, Rocket};

use sqlx::ConnectOptions;

pub type Db = sqlx::SqlitePool;

pub type Result<T, E = rocket::response::Debug<sqlx::Error>> = std::result::Result<T, E>;

async fn init_db(rocket: Rocket<Build>) -> fairing::Result {
    let mut opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("./test_elections/test_election.sqlite.db")
        .create_if_missing(true);

    opts.disable_statement_logging();
    let db = match Db::connect_with(opts).await {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to connect to SQLx database: {}", e);
            return Err(rocket);
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&db).await {
        error!("Failed to initialize SQLx database: {}", e);
        return Err(rocket);
    }

    // Fill the in-memory store
    fill_store(&db).await;

    Ok(rocket.manage(db))
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("SQLx Stage", |rocket| async {
        rocket.attach(AdHoc::try_on_ignite("SQLx Database", init_db))
    })
}

async fn fill_store(db: &Db) {
    use crate::rocket::futures::TryStreamExt;

    let records: Vec<cryptoballot::SignedTransaction> =
        sqlx::query!("SELECT tx_value FROM tx ORDER BY id",)
            .fetch(db)
            .map_ok(|r| serde_json::from_str(&r.tx_value).unwrap())
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

    let mut store = crate::MEM_STORE.lock().unwrap();
    for record in records {
        store.set(record);
    }
}
