use std::fmt;

/// Errors returned by the ecash library.
#[derive(Debug)]
pub enum Error {
    /// No mint key exists for the requested denomination.
    UnknownDenomination(u64),
    /// The note's signature did not match the mint key (`C != x·Y`).
    InvalidSignature,
    /// The note's secret was already spent.
    DoubleSpend,
    /// A swap's inputs and outputs did not preserve value.
    ValueMismatch { inputs: u64, outputs: u64 },
    /// The wallet could not select notes summing exactly to the requested amount.
    SelectionFailed { requested: u64, selected: u64 },
    /// A scalar was zero or out of range for the curve order.
    InvalidScalar,
    /// An underlying secp256k1 operation failed.
    Secp(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownDenomination(v) => write!(f, "unknown denomination: {v}"),
            Error::InvalidSignature => write!(f, "invalid note signature"),
            Error::DoubleSpend => write!(f, "note already spent"),
            Error::ValueMismatch { inputs, outputs } => {
                write!(f, "value mismatch: inputs {inputs} != outputs {outputs}")
            }
            Error::SelectionFailed {
                requested,
                selected,
            } => write!(
                f,
                "could not select notes for {requested} (selected {selected})"
            ),
            Error::InvalidScalar => write!(f, "invalid scalar"),
            Error::Secp(e) => write!(f, "secp256k1 error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp(e)
    }
}

/// Convenience alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;
