use std::collections::BTreeMap;
use std::fmt;

use secp256k1::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Stable identifier for a mint's set of denomination keys, derived
/// deterministically from the public keys it contains. Two mints with the same
/// public keys share an id; any change to the keys changes the id.
///
/// Serialized as a 64-character lowercase hex string.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeysetId([u8; 32]);

impl KeysetId {
    /// Derive the id from denomination public keys. `pubkeys` is a `BTreeMap`, so
    /// iteration is ordered by denomination and the result is canonical.
    pub fn derive(pubkeys: &BTreeMap<u64, PublicKey>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"dmto_keyset_id_v1");
        for (value, pk) in pubkeys {
            hasher.update(value.to_be_bytes());
            hasher.update(pk.serialize());
        }
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            fmt::write(&mut s, format_args!("{b:02x}")).expect("writing to String cannot fail");
        }
        s
    }

    /// Parse a 64-character hex string back into a `KeysetId`.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(format!("expected 64 hex chars, got {}", s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex: {e}"))?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for KeysetId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeysetId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for KeysetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for KeysetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeysetId({})", self.to_hex())
    }
}

/// The public half of a mint's keyset: the id plus the per-denomination public
/// keys, suitable for a wallet to fetch and verify against.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyset {
    pub id: KeysetId,
    pub keys: BTreeMap<u64, PublicKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::Mint;

    #[test]
    fn id_matches_derive_over_public_keyset() {
        let mint = Mint::new(&[1, 2, 4]);
        let ks = mint.public_keyset();
        assert_eq!(mint.id(), KeysetId::derive(&ks.keys));
    }

    #[test]
    fn different_mints_have_different_ids() {
        let a = Mint::new(&[1, 2, 4]);
        let b = Mint::new(&[1, 2, 4]);
        // Keys are random per mint, so ids differ despite identical denominations.
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn hex_is_64_chars() {
        let mint = Mint::new(&[1]);
        assert_eq!(mint.id().to_hex().len(), 64);
    }

    #[test]
    fn serializes_as_hex_string_and_roundtrips() {
        let mint = Mint::new(&[1, 2, 4]);
        let id = mint.id();
        let json = serde_json::to_string(&id).unwrap();
        // A JSON string, not an array.
        assert_eq!(json, format!("\"{}\"", id.to_hex()));
        let id2: KeysetId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn public_keyset_serde_roundtrip() {
        let mint = Mint::new(&[1, 2, 4]);
        let ks = mint.public_keyset();
        let ks2: PublicKeyset = serde_json::from_str(&serde_json::to_string(&ks).unwrap()).unwrap();
        assert_eq!(ks.id, ks2.id);
        assert_eq!(ks.keys, ks2.keys);
    }
}
