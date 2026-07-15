//! dmto-relay: the network server.
//!
//! Phase 1 hosts the mint's HTTP API (issue / swap / melt / keyset). Later phases
//! add message routing and store-and-forward on top of the same server.

mod exchange;
mod mint_api;
mod store;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use dmto_ecash::{
    api::{
        ExchangeRate, MeltRequest, MeltResponse, MintInfo, MintRequest, SignatureResponse,
        SupplyResponse, SwapRequest,
    },
    issuer::IssuerId,
    keyset::PublicKeyset,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use exchange::Exchange;
use mint_api::{AppError, MintApi, PgMint};

/// Default denominations (powers of two) each mint is initialized with.
const DENOMINATIONS: &[u64] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        let user = std::env::var("USER").unwrap_or_else(|_| "postgres".to_string());
        format!("postgres://{user}@localhost/dmto")
    });
    let pool = PgPoolOptions::new().connect(&db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    // Primary mint serves the single-mint API; the secondary lets us demonstrate
    // cross-issuer exchange within one relay.
    let primary = Arc::new(load_mint(&pool, "primary").await?);
    let secondary = Arc::new(load_mint(&pool, "secondary").await?);
    println!(
        "dmto-relay primary issuer {} keyset {}",
        primary.mint_info().issuer,
        primary.keyset_id()
    );
    println!(
        "dmto-relay secondary issuer {} keyset {}",
        secondary.mint_info().issuer,
        secondary.keyset_id()
    );

    // Posted rates: 1 primary = 2 secondary, 2 secondary = 1 primary.
    let rates = vec![
        ExchangeRate {
            from: primary.keyset_id(),
            to: secondary.keyset_id(),
            num: 2,
            den: 1,
        },
        ExchangeRate {
            from: secondary.keyset_id(),
            to: primary.keyset_id(),
            num: 1,
            den: 2,
        },
    ];
    let mints = HashMap::from([
        (primary.keyset_id(), primary.clone()),
        (secondary.keyset_id(), secondary.clone()),
    ]);
    let ex = Arc::new(Exchange::new(mints, rates));

    let app = app(primary).merge(exchange::router(ex));

    let addr = std::env::var("DMTO_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("dmto-relay listening on {addr}");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Load (or create) the mint for `label`, including its persisted issuer key.
async fn load_mint(pool: &PgPool, label: &str) -> Result<PgMint, Box<dyn std::error::Error>> {
    let keys = store::load_or_create_keys(pool, label, DENOMINATIONS).await?;
    let issuer_sk: SecretKey = store::load_or_create_issuer(pool, label).await?;
    let issuer = IssuerId::new(PublicKey::from_secret_key(&Secp256k1::new(), &issuer_sk));
    Ok(PgMint::new(pool.clone(), label, keys, issuer))
}

/// Build the router over any [`MintApi`]. Generic so tests can supply an
/// in-memory mint while `main` supplies the Postgres-backed one.
fn app<M: MintApi>(mint: Arc<M>) -> Router {
    Router::new()
        .route("/v1/info", get(info::<M>))
        .route("/v1/keyset", get(keyset::<M>))
        .route("/v1/supply", get(supply::<M>))
        .route("/v1/mint", post(mint_ecash::<M>))
        .route("/v1/swap", post(swap::<M>))
        .route("/v1/melt", post(melt::<M>))
        .with_state(mint)
}

async fn info<M: MintApi>(State(mint): State<Arc<M>>) -> Json<MintInfo> {
    Json(mint.mint_info())
}

async fn supply<M: MintApi>(State(mint): State<Arc<M>>) -> Result<Json<SupplyResponse>, AppError> {
    Ok(Json(mint.supply().await?))
}

async fn keyset<M: MintApi>(State(mint): State<Arc<M>>) -> Json<PublicKeyset> {
    Json(mint.public_keyset())
}

async fn mint_ecash<M: MintApi>(
    State(mint): State<Arc<M>>,
    Json(req): Json<MintRequest>,
) -> Result<Json<SignatureResponse>, AppError> {
    Ok(Json(mint.process_mint(req).await?))
}

async fn swap<M: MintApi>(
    State(mint): State<Arc<M>>,
    Json(req): Json<SwapRequest>,
) -> Result<Json<SignatureResponse>, AppError> {
    Ok(Json(mint.process_swap(req).await?))
}

async fn melt<M: MintApi>(
    State(mint): State<Arc<M>>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, AppError> {
    Ok(Json(mint.process_melt(req).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use dmto_ecash::api::BlindedOutput;
    use dmto_ecash::blind::{blind_message, unblind_signature};
    use dmto_ecash::hash::hash_to_curve;
    use dmto_ecash::mint::Mint;
    use dmto_ecash::types::Note;
    use http_body_util::BodyExt;
    use mint_api::InMemoryMint;
    use tower::ServiceExt;

    fn in_memory(denoms: &[u64]) -> Arc<InMemoryMint> {
        Arc::new(InMemoryMint::new(Mint::new(denoms)))
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<Vec<u8>>,
    ) -> (StatusCode, Vec<u8>) {
        let builder = Request::builder().method(method).uri(uri);
        let req = match body {
            Some(bytes) => builder
                .header("content-type", "application/json")
                .body(Body::from(bytes))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn keyset_is_served() {
        let mint = in_memory(&[1, 2, 4]);
        let expected = mint.public_keyset().id;
        let (status, body) = send(app(mint), "GET", "/v1/keyset", None).await;
        assert_eq!(status, StatusCode::OK);
        let ks: PublicKeyset = serde_json::from_slice(&body).unwrap();
        assert_eq!(ks.id, expected);
    }

    #[tokio::test]
    async fn info_is_served() {
        let mint = in_memory(&[1, 2, 4]);
        let expected = mint.mint_info();
        let (status, body) = send(app(mint), "GET", "/v1/info", None).await;
        assert_eq!(status, StatusCode::OK);
        let info: MintInfo = serde_json::from_slice(&body).unwrap();
        assert_eq!(info.issuer, expected.issuer);
        assert_eq!(info.keyset.id, expected.keyset.id);
    }

    #[tokio::test]
    async fn mint_then_melt_over_http() {
        let mint = in_memory(&[1, 2, 4, 8]);
        let pubkey = mint.public_keyset().keys[&4];

        // Client blinds a value-4 output and asks the mint to sign it.
        let secret = b"client-secret".to_vec();
        let y = hash_to_curve(&secret);
        let bm = blind_message(&y).unwrap();
        let mint_req = MintRequest {
            outputs: vec![BlindedOutput {
                value: 4,
                blinded_point: bm.blinded_point,
            }],
        };

        let (status, body) = send(
            app(mint.clone()),
            "POST",
            "/v1/mint",
            Some(serde_json::to_vec(&mint_req).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let sigs: SignatureResponse = serde_json::from_slice(&body).unwrap();

        // Client unblinds into a spendable note.
        let c = unblind_signature(&sigs.signatures[0].c_prime, &bm.blind_factor, &pubkey).unwrap();
        let note = Note {
            value: 4,
            secret,
            y,
            c,
        };

        // Melt the note back to the mint.
        let melt_req = MeltRequest { inputs: vec![note] };
        let (status, body) = send(
            app(mint.clone()),
            "POST",
            "/v1/melt",
            Some(serde_json::to_vec(&melt_req).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resp: MeltResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.melted, 4);

        // Re-melting the same note is a double-spend -> 409.
        let (status, _) = send(
            app(mint),
            "POST",
            "/v1/melt",
            Some(serde_json::to_vec(&melt_req).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn unknown_denomination_is_bad_request() {
        let mint = in_memory(&[1, 2, 4]);
        let y = hash_to_curve(b"x");
        let bm = blind_message(&y).unwrap();
        let req = MintRequest {
            outputs: vec![BlindedOutput {
                value: 3, // not a denomination
                blinded_point: bm.blinded_point,
            }],
        };
        let (status, _) = send(
            app(mint),
            "POST",
            "/v1/mint",
            Some(serde_json::to_vec(&req).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Verifies double-spend protection is backed by the database: a fresh
    /// `PgMint` (empty of any in-memory spent set) still rejects a note that an
    /// earlier instance already melted. Requires Postgres; ignored by default.
    ///
    /// Run with: `cargo test -p dmto-relay -- --ignored pg_spend_persists`
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn pg_spend_persists_across_instances() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            let user = std::env::var("USER").unwrap_or_else(|_| "postgres".to_string());
            format!("postgres://{user}@localhost/dmto")
        });
        let pool = PgPoolOptions::new().connect(&db_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let keys = store::load_or_create_keys(&pool, "primary", DENOMINATIONS)
            .await
            .unwrap();
        let issuer_sk = store::load_or_create_issuer(&pool, "primary")
            .await
            .unwrap();
        let issuer = IssuerId::new(PublicKey::from_secret_key(&Secp256k1::new(), &issuer_sk));

        let mint1 = PgMint::new(pool.clone(), "primary", keys.clone(), issuer);
        let pubkey = mint1.public_keyset().keys[&4];

        // Issue a value-4 note (unique secret so reruns don't collide).
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let secret = format!("pg-test-{nanos}").into_bytes();
        let y = hash_to_curve(&secret);
        let bm = blind_message(&y).unwrap();
        let resp = mint1
            .process_mint(MintRequest {
                outputs: vec![BlindedOutput {
                    value: 4,
                    blinded_point: bm.blinded_point,
                }],
            })
            .await
            .unwrap();
        let c = unblind_signature(&resp.signatures[0].c_prime, &bm.blind_factor, &pubkey).unwrap();
        let note = Note {
            value: 4,
            secret,
            y,
            c,
        };

        // First melt succeeds.
        let melted = mint1
            .process_melt(MeltRequest {
                inputs: vec![note.clone()],
            })
            .await
            .unwrap();
        assert_eq!(melted.melted, 4);

        // A brand-new instance sharing the pool rejects the same note.
        let mint2 = PgMint::new(pool, "primary", keys, issuer);
        let result = mint2.process_melt(MeltRequest { inputs: vec![note] }).await;
        assert!(matches!(
            result,
            Err(AppError::Ecash(dmto_ecash::Error::DoubleSpend))
        ));
    }
}
