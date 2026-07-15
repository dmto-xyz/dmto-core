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
        ApiError, BlindSignature, BlindedOutput, MeltRequest, MeltResponse, MintInfo, MintRequest,
        SignatureResponse, SupplyResponse, SwapRequest,
    },
    blind::blind_sign,
    issuer::IssuerId,
    keyset::{KeysetId, PublicKeyset},
    mint::MintKey,
    types::Note,
};
use secp256k1::PublicKey;
use sqlx::{PgPool, Row};

/// Error returned by mint operations, convertible to an HTTP response.
#[derive(Debug)]
pub enum AppError {
    /// A domain error from the ecash core.
    Ecash(Error),
    /// A relay-level bad request (e.g. an unknown keyset or unsupported rate).
    BadRequest(String),
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
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
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
    fn mint_info(&self) -> MintInfo;
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
    fn supply(&self) -> impl Future<Output = Result<SupplyResponse, AppError>> + Send;
}

/// In-memory mint (spent set lives in the process). Used in tests.
#[cfg(test)]
pub struct InMemoryMint {
    mint: dmto_ecash::mint::Mint,
    issuer: IssuerId,
}

#[cfg(test)]
impl InMemoryMint {
    pub fn new(mint: dmto_ecash::mint::Mint) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());
        let issuer = IssuerId::new(PublicKey::from_secret_key(&secp, &sk));
        Self { mint, issuer }
    }
}

#[cfg(test)]
impl MintApi for InMemoryMint {
    fn public_keyset(&self) -> PublicKeyset {
        self.mint.public_keyset()
    }

    fn mint_info(&self) -> MintInfo {
        MintInfo {
            issuer: self.issuer,
            keyset: self.mint.public_keyset(),
        }
    }

    async fn process_mint(&self, req: MintRequest) -> Result<SignatureResponse, AppError> {
        Ok(self.mint.process_mint(req)?)
    }

    async fn process_swap(&self, req: SwapRequest) -> Result<SignatureResponse, AppError> {
        Ok(self.mint.process_swap(req)?)
    }

    async fn process_melt(&self, req: MeltRequest) -> Result<MeltResponse, AppError> {
        Ok(self.mint.process_melt(req)?)
    }

    async fn supply(&self) -> Result<SupplyResponse, AppError> {
        Ok(self.mint.supply())
    }
}

/// Postgres-backed mint: signing keys held in memory, spent secrets in the database.
pub struct PgMint {
    pool: PgPool,
    label: String,
    keys: HashMap<u64, MintKey>,
    id: KeysetId,
    issuer: IssuerId,
}

impl PgMint {
    pub fn new(
        pool: PgPool,
        label: impl Into<String>,
        mint_keys: Vec<MintKey>,
        issuer: IssuerId,
    ) -> Self {
        let keys: HashMap<u64, MintKey> = mint_keys.into_iter().map(|k| (k.value, k)).collect();
        let pubkeys = keys.iter().map(|(&v, k)| (v, k.pubkey)).collect();
        let id = KeysetId::derive(&pubkeys);
        Self {
            pool,
            label: label.into(),
            keys,
            id,
            issuer,
        }
    }

    pub fn keyset_id(&self) -> KeysetId {
        self.id
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

    /// Spend `inputs` and record `issued` outputs in a single transaction: either
    /// all changes commit or none do (on error the transaction rolls back).
    async fn apply(&self, inputs: &[Note], issued: &[BlindedOutput]) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        for note in inputs {
            let key = self
                .keys
                .get(&note.value)
                .ok_or(Error::UnknownDenomination(note.value))?;
            if !key.verify_note(note)? {
                return Err(Error::InvalidSignature.into());
            }
            let result =
                sqlx::query("INSERT INTO spent_secret (label, secret, value) VALUES ($1, $2, $3)")
                    .bind(&self.label)
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
        for out in issued {
            sqlx::query(
                "INSERT INTO issued_total (label, value, total) VALUES ($1, $2, $3)
                 ON CONFLICT (label, value) DO UPDATE SET total = issued_total.total + EXCLUDED.total",
            )
            .bind(&self.label)
            .bind(out.value as i64)
            .bind(out.value as i64)
            .execute(&mut *tx)
            .await?;
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

    fn mint_info(&self) -> MintInfo {
        MintInfo {
            issuer: self.issuer,
            keyset: self.public_keyset(),
        }
    }

    async fn process_mint(&self, req: MintRequest) -> Result<SignatureResponse, AppError> {
        self.require_known_denoms(&req.outputs)?;
        self.apply(&[], &req.outputs).await?;
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
        self.apply(&req.inputs, &req.outputs).await?;
        self.sign_outputs(&req.outputs)
    }

    async fn process_melt(&self, req: MeltRequest) -> Result<MeltResponse, AppError> {
        let melted = req.inputs.iter().map(|n| n.value).sum();
        self.apply(&req.inputs, &[]).await?;
        Ok(MeltResponse { melted })
    }

    async fn supply(&self) -> Result<SupplyResponse, AppError> {
        let issued_rows = sqlx::query("SELECT value, total FROM issued_total WHERE label = $1")
            .bind(&self.label)
            .fetch_all(&self.pool)
            .await?;
        let redeemed_rows = sqlx::query(
            "SELECT value, SUM(value)::BIGINT AS redeemed FROM spent_secret WHERE label = $1 GROUP BY value",
        )
        .bind(&self.label)
        .fetch_all(&self.pool)
        .await?;

        let mut per_denom: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
        let mut issued = 0u64;
        for row in issued_rows {
            let value: i64 = row.get("value");
            let total: i64 = row.get("total");
            per_denom.insert(value as u64, total as u64);
            issued += total as u64;
        }
        let mut redeemed = 0u64;
        for row in redeemed_rows {
            let value: i64 = row.get("value");
            let r: i64 = row.get("redeemed");
            redeemed += r as u64;
            let entry = per_denom.entry(value as u64).or_insert(0);
            *entry = entry.saturating_sub(r as u64);
        }

        Ok(SupplyResponse {
            issued,
            redeemed,
            outstanding: issued.saturating_sub(redeemed),
            per_denom,
        })
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .map(|d| d.is_unique_violation())
        .unwrap_or(false)
}
