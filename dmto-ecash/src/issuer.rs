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
    }
}
