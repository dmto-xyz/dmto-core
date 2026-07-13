//! dmto-relay: the network server.
//!
//! Phase 1 hosts the mint's HTTP API (issue / swap / melt / keyset). Later phases
//! add message routing and store-and-forward on top of the same server.

mod store;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dmto_ecash::{
    Error,
    api::{ApiError, MeltRequest, MeltResponse, MintRequest, SignatureResponse, SwapRequest},
    keyset::PublicKeyset,
    mint::Mint,
};
use sqlx::postgres::PgPoolOptions;

type SharedMint = Arc<Mint>;

/// Default denominations (powers of two) the mint is initialized with.
const DENOMINATIONS: &[u64] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        let user = std::env::var("USER").unwrap_or_else(|_| "postgres".to_string());
        format!("postgres://{user}@localhost/dmto")
    });
    let pool = PgPoolOptions::new().connect(&db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let mint = Arc::new(store::load_or_create_mint(&pool, DENOMINATIONS).await?);
    println!("dmto-relay mint keyset: {}", mint.id());

    let addr = std::env::var("DMTO_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("dmto-relay listening on {addr}");

    axum::serve(listener, app(mint)).await?;
    Ok(())
}

/// Build the router. Separated from `main` so tests can drive it directly.
fn app(mint: SharedMint) -> Router {
    Router::new()
        .route("/v1/keyset", get(keyset))
        .route("/v1/mint", post(mint_ecash))
        .route("/v1/swap", post(swap))
        .route("/v1/melt", post(melt))
        .with_state(mint)
}

async fn keyset(State(mint): State<SharedMint>) -> Json<PublicKeyset> {
    Json(mint.public_keyset())
}

async fn mint_ecash(
    State(mint): State<SharedMint>,
    Json(req): Json<MintRequest>,
) -> Result<Json<SignatureResponse>, AppError> {
    Ok(Json(mint.process_mint(req)?))
}

async fn swap(
    State(mint): State<SharedMint>,
    Json(req): Json<SwapRequest>,
) -> Result<Json<SignatureResponse>, AppError> {
    Ok(Json(mint.process_swap(req)?))
}

async fn melt(
    State(mint): State<SharedMint>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, AppError> {
    Ok(Json(mint.process_melt(req)?))
}

/// Wraps a library [`Error`] so it can be turned into an HTTP response.
struct AppError(Error);

impl From<Error> for AppError {
    fn from(e: Error) -> Self {
        AppError(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::DoubleSpend => StatusCode::CONFLICT,
            // Everything else is a malformed or invalid client request.
            _ => StatusCode::BAD_REQUEST,
        };
        let body = Json(ApiError {
            error: self.0.to_string(),
        });
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use dmto_ecash::api::BlindedOutput;
    use dmto_ecash::blind::{blind_message, unblind_signature};
    use dmto_ecash::hash::hash_to_curve;
    use dmto_ecash::types::Note;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
        let mint = Arc::new(Mint::new(&[1, 2, 4]));
        let (status, body) = send(app(mint.clone()), "GET", "/v1/keyset", None).await;
        assert_eq!(status, StatusCode::OK);
        let ks: PublicKeyset = serde_json::from_slice(&body).unwrap();
        assert_eq!(ks.id, mint.id());
    }

    #[tokio::test]
    async fn mint_then_melt_over_http() {
        let mint = Arc::new(Mint::new(&[1, 2, 4, 8]));
        let pubkey = mint.keys.get(&4).unwrap().pubkey;

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
        let mint = Arc::new(Mint::new(&[1, 2, 4]));
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
}
