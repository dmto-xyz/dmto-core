//! Chaumian ecash (Cashu-style BDHKE) over secp256k1.
//!
//! See `SPEC.md` §2 for the design and `docs/blindsign.md` for the underlying math.

pub mod api;
pub mod blind;
pub mod error;
pub mod hash;
pub mod keyset;
pub mod mint;
pub mod types;
pub mod wallet;

pub use error::{Error, Result};
