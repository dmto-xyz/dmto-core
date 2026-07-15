//! Blocking HTTP client for the relay's mint API.

use std::error::Error;

use dmto_ecash::api::{
    ApiError, ExchangeRequest, MeltRequest, MeltResponse, MintInfo, MintRequest, RatesResponse,
    SignatureResponse,
};
use dmto_ecash::keyset::PublicKeyset;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub struct MintClient {
    base: String,
    http: reqwest::blocking::Client,
}

impl MintClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: reqwest::blocking::Client::new(),
        }
    }

    pub fn info(&self) -> Result<MintInfo, Box<dyn Error>> {
        let resp = self.http.get(self.url("/v1/info")).send()?;
        Self::read(resp)
    }

    pub fn keyset(&self) -> Result<PublicKeyset, Box<dyn Error>> {
        let resp = self.http.get(self.url("/v1/keyset")).send()?;
        Self::read(resp)
    }

    pub fn mint(&self, req: &MintRequest) -> Result<SignatureResponse, Box<dyn Error>> {
        self.post("/v1/mint", req)
    }

    pub fn melt(&self, req: &MeltRequest) -> Result<MeltResponse, Box<dyn Error>> {
        self.post("/v1/melt", req)
    }

    pub fn rates(&self) -> Result<RatesResponse, Box<dyn Error>> {
        let resp = self.http.get(self.url("/v1/rates")).send()?;
        Self::read(resp)
    }

    pub fn exchange(&self, req: &ExchangeRequest) -> Result<SignatureResponse, Box<dyn Error>> {
        self.post("/v1/exchange", req)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, Box<dyn Error>> {
        let resp = self.http.post(self.url(path)).json(body).send()?;
        Self::read(resp)
    }

    /// Read a JSON response, turning a non-2xx status into the server's `ApiError`
    /// message (or a generic status message if the body isn't an `ApiError`).
    fn read<R: DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<R, Box<dyn Error>> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json()?)
        } else {
            let msg = resp
                .json::<ApiError>()
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("HTTP {status}"));
            Err(msg.into())
        }
    }
}
