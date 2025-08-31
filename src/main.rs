//! Application entrypoint and state wiring.

mod crypto;
mod model;
mod routes;
mod storage;

use axum::{
    routing::{get, post},
    Router,
};
use crypto::{generate_keypair, load_key, save_key, Keypair};
use model::Ledger;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Shared application state passed to Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub keypair: Arc<crypto::Keypair>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub data_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    // 0) dirs
    let data_dir = PathBuf::from("data");
    storage::ensure_dir(&data_dir).expect("create data dir");

    // 1) key persistence
    let key_path = data_dir.join("key.bin");
    println!("Key path: {}", key_path.display());

    let signing = match load_key(&key_path).expect("load key file") {
    Some(k) => {
        println!("Loaded existing key from disk");
        k
    }
    None => {
        println!("No key found on disk; generating and saving a new key");
        let kp = generate_keypair();
        save_key(&key_path, &kp.signing).expect("save key");
        kp.signing
    }
    };

    let verifying = signing.verifying_key();
    let keypair = Keypair { signing, verifying };
    println!(
        "Public key (hex): {}",
        hex::encode(keypair.verifying.to_bytes())
    );

    // 2) load existing blocks
    let blocks = storage::load_blocks(&data_dir).expect("load blocks");
    let ledger = Ledger { blocks };
    println!("Loaded {} block(s) from disk", ledger.blocks.len());

    // 3) shared state
    let state = AppState {
        keypair: Arc::new(keypair),
        ledger: Arc::new(Mutex::new(ledger)),
        data_dir,
    };

    // 4) router
    let app = Router::new()
        .route("/receipt", post(routes::add_receipt))
        .route("/receipt/:id", get(routes::get_receipt))
        .route("/receipts", get(routes::list_receipts))
        .route("/validate", get(routes::validate_chain))
        .route("/pubkey", get(routes::pubkey))
        .route("/health", get(routes::health))
        .route("/version", get(routes::version))
        .with_state(state);

    // 5) serve
    let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    println!(" running on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
