//! Postgres-backed persistence for the relay's mint: the keyset (signing keys,
//! so the keyset id is stable across restarts) and the spent-secret set.

use std::fmt;

use dmto_ecash::mint::MintKey;
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

/// Load the relay's issuer private key, generating and persisting one the first
/// time. The issuer identity (its public key) is thus stable across restarts.
pub async fn load_or_create_issuer(pool: &PgPool) -> Result<SecretKey, StoreError> {
    if let Some(row) = sqlx::query("SELECT privkey FROM issuer_key LIMIT 1")
        .fetch_optional(pool)
        .await?
    {
        let bytes: Vec<u8> = row.get("privkey");
        return SecretKey::from_slice(&bytes).map_err(|e| StoreError::BadKey(e.to_string()));
    }

    let sk = SecretKey::new(&mut secp256k1::rand::thread_rng());
    sqlx::query("INSERT INTO issuer_key (privkey) VALUES ($1)")
        .bind(sk.secret_bytes().to_vec())
        .execute(pool)
        .await?;
    Ok(sk)
}

/// Load the mint's signing keys from the database, generating and persisting a
/// fresh set for `denoms` the first time (when the table is empty).
pub async fn load_or_create_keys(
    pool: &PgPool,
    denoms: &[u64],
) -> Result<Vec<MintKey>, StoreError> {
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
        Ok(keys)
    } else {
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            let value: i64 = row.get("value");
            let bytes: Vec<u8> = row.get("privkey");
            let sk =
                SecretKey::from_slice(&bytes).map_err(|e| StoreError::BadKey(e.to_string()))?;
            keys.push(MintKey::from_privkey(value as u64, sk));
        }
        Ok(keys)
    }
}
