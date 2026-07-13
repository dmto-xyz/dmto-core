//! The mint service abstraction and its two implementations.
//!
//! - [`InMemoryMint`] wraps the in-memory [`Mint`] and is used by the fast HTTP
//!   tests (no database required).
//! - [`PgMint`] persists the spent-secret set in Postgres, so double-spend
//!   protection survives restarts.

use std::collections::HashMap;
use std::future::Future;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dmto_ecash::{
    Error,
    api::{
        ApiError, BlindSignature, BlindedOutput, MeltRequest, MeltResponse, MintRequest,
        SignatureResponse, SwapRequest,
    },
    blind::blind_sign,
    keyset::{KeysetId, PublicKeyset},
    mint::MintKey,
    types::Note,
};
use secp256k1::PublicKey;
use sqlx::PgPool;

/// Error returned by mint operations, convertible to an HTTP response.
#[derive(Debug)]
pub enum AppError {
    /// A domain error from the ecash core.
    Ecash(Error),
    /// A database error.
    Db(sqlx::Error),
}

impl From<Error> for AppError {
    fn from(e: Error) -> Self {
        AppError::Ecash(e)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Db(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Ecash(Error::DoubleSpend) => {
                (StatusCode::CONFLICT, Error::DoubleSpend.to_string())
            }
            AppError::Ecash(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::Db(e) => {
                // Don't leak database internals to clients.
                eprintln!("database error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(ApiError { error: message })).into_response()
    }
}

/// The operations the relay's HTTP handlers depend on.
///
/// Methods return `impl Future + Send` (rather than bare `async fn`) so the
/// handler futures are `Send`, as axum requires for generic state.
pub trait MintApi: Send + Sync + 'static {
    fn public_keyset(&self) -> PublicKeyset;
    fn process_mint(
        &self,
        req: MintRequest,
    ) -> impl Future<Output = Result<SignatureResponse, AppError>> + Send;
    fn process_swap(
        &self,
        req: SwapRequest,
    ) -> impl Future<Output = Result<SignatureResponse, AppError>> + Send;
    fn process_melt(
        &self,
        req: MeltRequest,
    ) -> impl Future<Output = Result<MeltResponse, AppError>> + Send;
}

/// In-memory mint (spent set lives in the process). Used in tests.
#[cfg(test)]
pub struct InMemoryMint(pub dmto_ecash::mint::Mint);

#[cfg(test)]
impl MintApi for InMemoryMint {
    fn public_keyset(&self) -> PublicKeyset {
        self.0.public_keyset()
    }

    async fn process_mint(&self, req: MintRequest) -> Result<SignatureResponse, AppError> {
        Ok(self.0.process_mint(req)?)
    }

    async fn process_swap(&self, req: SwapRequest) -> Result<SignatureResponse, AppError> {
        Ok(self.0.process_swap(req)?)
    }

    async fn process_melt(&self, req: MeltRequest) -> Result<MeltResponse, AppError> {
        Ok(self.0.process_melt(req)?)
    }
}

/// Postgres-backed mint: signing keys held in memory, spent secrets in the database.
pub struct PgMint {
    pool: PgPool,
    keys: HashMap<u64, MintKey>,
    id: KeysetId,
}

impl PgMint {
    pub fn new(pool: PgPool, mint_keys: Vec<MintKey>) -> Self {
        let keys: HashMap<u64, MintKey> = mint_keys.into_iter().map(|k| (k.value, k)).collect();
        let pubkeys = keys.iter().map(|(&v, k)| (v, k.pubkey)).collect();
        let id = KeysetId::derive(&pubkeys);
        Self { pool, keys, id }
    }

    /// Blind-sign each output, failing if a denomination is unknown.
    fn sign_outputs(&self, outputs: &[BlindedOutput]) -> Result<SignatureResponse, AppError> {
        let mut signatures = Vec::with_capacity(outputs.len());
        for out in outputs {
            let key = self
                .keys
                .get(&out.value)
                .ok_or(Error::UnknownDenomination(out.value))?;
            let (c_prime, dleq) = blind_sign(&key.privkey, &out.blinded_point)?;
            signatures.push(BlindSignature {
                value: out.value,
                c_prime,
                dleq,
            });
        }
        Ok(SignatureResponse { signatures })
    }

    /// Verify and spend all `notes` in a single transaction. Either all are
    /// recorded as spent or none are (on error the transaction rolls back).
    async fn spend_all(&self, notes: &[Note]) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        for note in notes {
            let key = self
                .keys
                .get(&note.value)
                .ok_or(Error::UnknownDenomination(note.value))?;
            if !key.verify_note(note)? {
                return Err(Error::InvalidSignature.into());
            }
            let result = sqlx::query("INSERT INTO spent_secret (secret, value) VALUES ($1, $2)")
                .bind(&note.secret)
                .bind(note.value as i64)
                .execute(&mut *tx)
                .await;
            match result {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => return Err(Error::DoubleSpend.into()),
                Err(e) => return Err(e.into()),
            }
        }
        tx.commit().await?;
        Ok(())
    }

    fn require_known_denoms(&self, outputs: &[BlindedOutput]) -> Result<(), AppError> {
        for out in outputs {
            if !self.keys.contains_key(&out.value) {
                return Err(Error::UnknownDenomination(out.value).into());
            }
        }
        Ok(())
    }
}

impl MintApi for PgMint {
    fn public_keyset(&self) -> PublicKeyset {
        let keys: std::collections::BTreeMap<u64, PublicKey> =
            self.keys.iter().map(|(&v, k)| (v, k.pubkey)).collect();
        PublicKeyset { id: self.id, keys }
    }

    async fn process_mint(&self, req: MintRequest) -> Result<SignatureResponse, AppError> {
        self.sign_outputs(&req.outputs)
    }

    async fn process_swap(&self, req: SwapRequest) -> Result<SignatureResponse, AppError> {
        let in_sum: u64 = req.inputs.iter().map(|n| n.value).sum();
        let out_sum: u64 = req.outputs.iter().map(|o| o.value).sum();
        if in_sum != out_sum {
            return Err(Error::ValueMismatch {
                inputs: in_sum,
                outputs: out_sum,
            }
            .into());
        }
        // Validate outputs before spending, so a bad request can't burn inputs.
        self.require_known_denoms(&req.outputs)?;
        self.spend_all(&req.inputs).await?;
        self.sign_outputs(&req.outputs)
    }

    async fn process_melt(&self, req: MeltRequest) -> Result<MeltResponse, AppError> {
        let melted = req.inputs.iter().map(|n| n.value).sum();
        self.spend_all(&req.inputs).await?;
        Ok(MeltResponse { melted })
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .map(|d| d.is_unique_violation())
        .unwrap_or(false)
}
