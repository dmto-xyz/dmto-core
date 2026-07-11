use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub secret: Vec<u8>,
    pub y: PublicKey,
    pub c: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_to_curve;

    #[test]
    fn note_serde_roundtrip() {
        let y = hash_to_curve(b"secret");
        let note = Note {
            value: 4,
            secret: vec![1, 2, 3, 4],
            y,
            c: y,
        };
        let note2: Note = serde_json::from_str(&serde_json::to_string(&note).unwrap()).unwrap();
        assert!(note == note2);
    }
}
