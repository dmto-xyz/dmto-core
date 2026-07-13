//! Postgres-backed persistence for the relay's mint.
//!
//! Slice A persists the mint's keyset (signing keys) so the keyset id is stable
//! across restarts. The spent-secret set is persisted in a later slice.

use std::fmt;

use dmto_ecash::mint::{Mint, MintKey};
use secp256k1::SecretKey;
use sqlx::{PgPool, Row};

#[derive(Debug)]
pub enum StoreError {
    Db(sqlx::Error),
    /// A private key stored in the database could not be parsed.
    BadKey(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Db(e) => write!(f, "database error: {e}"),
            StoreError::BadKey(e) => write!(f, "invalid stored key: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Db(e)
    }
}

/// Load the mint's keyset from the database, generating and persisting a fresh
/// set for `denoms` the first time (when the table is empty).
pub async fn load_or_create_mint(pool: &PgPool, denoms: &[u64]) -> Result<Mint, StoreError> {
    let rows = sqlx::query("SELECT value, privkey FROM mint_key ORDER BY value")
        .fetch_all(pool)
        .await?;

    if rows.is_empty() {
        let mut keys = Vec::with_capacity(denoms.len());
        let mut tx = pool.begin().await?;
        for &value in denoms {
            let key = MintKey::new(value);
            sqlx::query("INSERT INTO mint_key (value, privkey) VALUES ($1, $2)")
                .bind(value as i64)
                .bind(key.privkey.secret_bytes().to_vec())
                .execute(&mut *tx)
                .await?;
            keys.push(key);
        }
        tx.commit().await?;
        Ok(Mint::from_mint_keys(keys))
    } else {
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            let value: i64 = row.get("value");
            let bytes: Vec<u8> = row.get("privkey");
            let sk =
                SecretKey::from_slice(&bytes).map_err(|e| StoreError::BadKey(e.to_string()))?;
            keys.push(MintKey::from_privkey(value as u64, sk));
        }
        Ok(Mint::from_mint_keys(keys))
    }
}
