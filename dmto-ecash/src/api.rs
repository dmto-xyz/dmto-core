//! Wire types for the mint's HTTP API, shared by the server and client.
//!
//! Endpoints (Phase 1):
//! - `GET  /v1/info`   → [`MintInfo`]
//! - `GET  /v1/keyset` → [`crate::keyset::PublicKeyset`]
//! - `GET  /v1/supply` → [`SupplyResponse`]
//! - `POST /v1/mint`   → [`MintRequest`] / [`SignatureResponse`]
//! - `POST /v1/swap`   → [`SwapRequest`] / [`SignatureResponse`]
//! - `POST /v1/melt`   → [`MeltRequest`] / [`MeltResponse`]

use std::collections::BTreeMap;

use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::blind::DLEQ;
use crate::issuer::IssuerId;
use crate::keyset::PublicKeyset;
use crate::types::Note;

/// Identity and keyset a wallet needs to trust and use an issuer.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MintInfo {
    pub issuer: IssuerId,
    pub keyset: PublicKeyset,
}

/// Total-supply accounting for the mint's keyset (SPEC §3.2). `outstanding` is
/// `issued − redeemed`, per denomination and in total.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyResponse {
    pub issued: u64,
    pub redeemed: u64,
    pub outstanding: u64,
    /// Outstanding value per denomination.
    pub per_denom: BTreeMap<u64, u64>,
}

/// A single blinded output the wallet asks the mint to sign: a denomination and
/// the blinded point `B' = Y + r·G`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedOutput {
    pub value: u64,
    pub blinded_point: PublicKey,
}

/// The mint's blind signature over one output, with its DLEQ proof.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindSignature {
    pub value: u64,
    pub c_prime: PublicKey,
    pub dleq: DLEQ,
}

/// Response carrying one blind signature per requested output, in order.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signatures: Vec<BlindSignature>,
}

/// Issue new ecash: the mint blind-signs the given outputs.
///
/// Issuance is currently unbacked (no payment/collateral); gating is a later
/// concern tied to the "backing of ecash units" open question.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MintRequest {
    pub outputs: Vec<BlindedOutput>,
}

/// Swap existing notes for freshly blind-signed outputs of equal total value.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SwapRequest {
    pub inputs: Vec<Note>,
    pub outputs: Vec<BlindedOutput>,
}

/// Redeem notes back to the mint (spend without receiving new outputs).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MeltRequest {
    pub inputs: Vec<Note>,
}

/// Result of a melt: the total value the mint accepted and burned.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeltResponse {
    pub melted: u64,
}

/// Error body returned by the mint for a failed request.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::blind_message;
    use crate::hash::hash_to_curve;
    use crate::mint::Mint;
    use crate::wallet::Wallet;

    fn sample_note() -> Note {
        let mint = Mint::new(&[1, 2, 4]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        w.notes.remove(0)
    }

    fn sample_blinded() -> BlindedOutput {
        let y = hash_to_curve(b"out");
        let bm = blind_message(&y).unwrap();
        BlindedOutput {
            value: 4,
            blinded_point: bm.blinded_point,
        }
    }

    #[test]
    fn swap_request_serde_roundtrip() {
        let req = SwapRequest {
            inputs: vec![sample_note()],
            outputs: vec![sample_blinded()],
        };
        let req2: SwapRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert!(req == req2);
    }

    #[test]
    fn mint_and_melt_request_serde_roundtrip() {
        let mint_req = MintRequest {
            outputs: vec![sample_blinded()],
        };
        let mint_req2: MintRequest =
            serde_json::from_str(&serde_json::to_string(&mint_req).unwrap()).unwrap();
        assert!(mint_req == mint_req2);

        let melt_req = MeltRequest {
            inputs: vec![sample_note()],
        };
        let melt_req2: MeltRequest =
            serde_json::from_str(&serde_json::to_string(&melt_req).unwrap()).unwrap();
        assert!(melt_req == melt_req2);
    }

    #[test]
    fn responses_serde_roundtrip() {
        let melt = MeltResponse { melted: 6 };
        let melt2: MeltResponse =
            serde_json::from_str(&serde_json::to_string(&melt).unwrap()).unwrap();
        assert!(melt == melt2);

        let err = ApiError {
            error: "note already spent".to_string(),
        };
        let err2: ApiError = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert!(err == err2);
    }
}
