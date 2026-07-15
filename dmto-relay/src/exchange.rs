//! Cross-issuer exchange (SPEC §3.3): converts one hosted issuer's ecash into
//! another's at a posted rate. The relay hosts both mints, so an exchange melts
//! the source notes and issues the destination notes.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::get, routing::post};
use dmto_ecash::{
    Error,
    api::{
        ExchangeRate, ExchangeRequest, MeltRequest, MintInfo, MintRequest, RatesResponse,
        SignatureResponse,
    },
    keyset::KeysetId,
};

use crate::mint_api::{AppError, MintApi, PgMint};

/// The exchange: the mints it hosts (by keyset id) and its posted rates.
pub struct Exchange {
    mints: HashMap<KeysetId, Arc<PgMint>>,
    rates: Vec<ExchangeRate>,
}

impl Exchange {
    pub fn new(mints: HashMap<KeysetId, Arc<PgMint>>, rates: Vec<ExchangeRate>) -> Self {
        Self { mints, rates }
    }

    fn rate(&self, from: KeysetId, to: KeysetId) -> Option<&ExchangeRate> {
        self.rates.iter().find(|r| r.from == from && r.to == to)
    }

    fn rates_response(&self) -> RatesResponse {
        let mints: Vec<MintInfo> = self.mints.values().map(|m| m.mint_info()).collect();
        RatesResponse {
            mints,
            rates: self.rates.clone(),
        }
    }

    async fn exchange(&self, req: ExchangeRequest) -> Result<SignatureResponse, AppError> {
        let rate = self
            .rate(req.from, req.to)
            .copied()
            .ok_or_else(|| AppError::BadRequest("no posted rate for that pair".into()))?;

        let in_sum: u64 = req.inputs.iter().map(|n| n.value).sum();
        let out_sum: u64 = req.outputs.iter().map(|o| o.value).sum();
        // Require the exact posted rate: out/in == num/den.
        if out_sum * rate.den != in_sum * rate.num {
            return Err(AppError::Ecash(Error::ValueMismatch {
                inputs: in_sum,
                outputs: out_sum,
            }));
        }

        let from = self
            .mints
            .get(&req.from)
            .ok_or_else(|| AppError::BadRequest("unknown source keyset".into()))?;
        let to = self
            .mints
            .get(&req.to)
            .ok_or_else(|| AppError::BadRequest("unknown destination keyset".into()))?;

        // Melt the source notes, then issue the destination notes.
        from.process_melt(MeltRequest { inputs: req.inputs })
            .await?;
        to.process_mint(MintRequest {
            outputs: req.outputs,
        })
        .await
    }
}

pub fn router(exchange: Arc<Exchange>) -> Router {
    Router::new()
        .route("/v1/rates", get(rates))
        .route("/v1/exchange", post(exchange_handler))
        .with_state(exchange)
}

async fn rates(State(ex): State<Arc<Exchange>>) -> Json<RatesResponse> {
    Json(ex.rates_response())
}

async fn exchange_handler(
    State(ex): State<Arc<Exchange>>,
    Json(req): Json<ExchangeRequest>,
) -> Result<Json<SignatureResponse>, AppError> {
    Ok(Json(ex.exchange(req).await?))
}
