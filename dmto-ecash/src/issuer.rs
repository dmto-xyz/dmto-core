use std::fmt;

use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// Stable identity of an ecash issuer: its public key. This is what trust
/// decisions and cross-issuer exchange key off of (SPEC §3.1, §3.4). Serialized
/// as a 66-character compressed-pubkey hex string.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IssuerId(PublicKey);

impl IssuerId {
    pub fn new(pubkey: PublicKey) -> Self {
        Self(pubkey)
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(66);
        for b in self.0.serialize() {
            fmt::write(&mut s, format_args!("{b:02x}")).expect("writing to String cannot fail");
        }
        s
    }

    /// Parse a 66-character compressed-pubkey hex string into an `IssuerId`.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 66 {
            return Err(format!("expected 66 hex chars, got {}", s.len()));
        }
        let mut bytes = [0u8; 33];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex: {e}"))?;
        }
        let pk = PublicKey::from_slice(&bytes).map_err(|e| format!("invalid pubkey: {e}"))?;
        Ok(Self(pk))
    }
}

impl fmt::Display for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuerId({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn hex_is_66_chars_and_serde_roundtrips() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let id = IssuerId::new(PublicKey::from_secret_key(&secp, &sk));

        assert_eq!(id.to_hex().len(), 66);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.to_hex()));
        let id2: IssuerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);

        // hex round-trip
        let id3 = IssuerId::from_hex(&id.to_hex()).unwrap();
        assert_eq!(id, id3);
        assert!(IssuerId::from_hex("nothex").is_err());
    }
}
