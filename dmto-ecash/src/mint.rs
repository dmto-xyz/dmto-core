use std::collections::{BTreeMap, HashMap};

use dashmap::DashSet;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::{
    blind::{DLEQ, blind_sign},
    error::{Error, Result},
    keyset::{KeysetId, PublicKeyset},
    types::Note,
};

#[derive(Clone)]
pub struct MintKey {
    pub value: u64,
    pub privkey: SecretKey,
    pub pubkey: PublicKey,
}

impl MintKey {
    pub fn new(value: u64) -> Self {
        let secp = Secp256k1::new();
        let privkey = SecretKey::new(&mut rand::thread_rng());
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        Self {
            value,
            privkey,
            pubkey,
        }
    }
}

pub struct Mint {
    pub id: KeysetId,
    pub keys: HashMap<u64, MintKey>,
    pub spent: DashSet<Vec<u8>>,
}

impl Mint {
    pub fn new(denoms: &[u64]) -> Self {
        let keys: HashMap<u64, MintKey> = denoms.iter().map(|&v| (v, MintKey::new(v))).collect();
        let id = KeysetId::derive(&Self::pubkey_map(&keys));
        Self {
            id,
            keys,
            spent: DashSet::new(),
        }
    }

    fn pubkey_map(keys: &HashMap<u64, MintKey>) -> BTreeMap<u64, PublicKey> {
        keys.iter().map(|(&v, k)| (v, k.pubkey)).collect()
    }

    /// This mint's keyset id.
    pub fn id(&self) -> KeysetId {
        self.id
    }

    /// The public keyset (id + per-denomination public keys) a wallet verifies against.
    pub fn public_keyset(&self) -> PublicKeyset {
        PublicKeyset {
            id: self.id,
            keys: Self::pubkey_map(&self.keys),
        }
    }

    /// Verify a note's signature and mark its secret spent. Returns
    /// [`Error::DoubleSpend`] if the secret was already used.
    pub fn verify_and_spend(&self, note: &Note) -> Result<()> {
        let key = self
            .keys
            .get(&note.value)
            .ok_or(Error::UnknownDenomination(note.value))?;

        let expected = note.y.mul_tweak(&Secp256k1::new(), &key.privkey.into())?;
        if note.c != expected {
            return Err(Error::InvalidSignature);
        }

        // `insert` returns false if the secret was already present, so the
        // check-and-mark is atomic against concurrent spends.
        if !self.spent.insert(note.secret.clone()) {
            return Err(Error::DoubleSpend);
        }

        Ok(())
    }

    /// Burn `inputs` and blindly sign `outputs`, requiring value conservation.
    pub fn swap(
        &self,
        inputs: Vec<Note>,
        outputs: Vec<(u64, PublicKey)>,
    ) -> Result<Vec<(PublicKey, DLEQ)>> {
        let in_sum: u64 = inputs.iter().map(|n| n.value).sum();
        let out_sum: u64 = outputs.iter().map(|(v, _)| *v).sum();

        if in_sum != out_sum {
            return Err(Error::ValueMismatch {
                inputs: in_sum,
                outputs: out_sum,
            });
        }

        // Validate output denominations before spending any input, so a bad
        // output request cannot burn the caller's notes.
        for (value, _) in &outputs {
            if !self.keys.contains_key(value) {
                return Err(Error::UnknownDenomination(*value));
            }
        }

        for n in &inputs {
            self.verify_and_spend(n)?;
        }

        let mut sigs = Vec::with_capacity(outputs.len());
        for (value, blinded) in outputs {
            let key = self
                .keys
                .get(&value)
                .ok_or(Error::UnknownDenomination(value))?;
            sigs.push(blind_sign(&key.privkey, &blinded)?);
        }

        Ok(sigs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::blind_message;
    use crate::hash::hash_to_curve;
    use crate::wallet::Wallet;

    #[test]
    fn mint_and_verify() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        let note = w.notes[0].clone();
        assert!(mint.verify_and_spend(&note).is_ok());
    }

    #[test]
    fn double_spend_rejected() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        let note = w.notes[0].clone();
        assert!(mint.verify_and_spend(&note).is_ok());
        assert!(matches!(
            mint.verify_and_spend(&note),
            Err(Error::DoubleSpend)
        ));
    }

    #[test]
    fn unknown_denomination_rejected() {
        let mint = Mint::new(&[1, 2]);
        let mut w = Wallet { notes: vec![] };
        assert!(matches!(
            w.mint_note(&mint, 5),
            Err(Error::UnknownDenomination(5))
        ));
    }

    #[test]
    fn invalid_signature_rejected() {
        let mint = Mint::new(&[1, 2, 4]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        let mut note = w.notes[0].clone();
        note.c = note.y; // corrupt: Y != x*Y
        assert!(matches!(
            mint.verify_and_spend(&note),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn swap_conserves_value() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        w.mint_note(&mint, 2).unwrap();
        let inputs = w.notes.clone();

        let mut outputs = vec![];
        for v in [4u64, 2u64] {
            let y = hash_to_curve(format!("out{v}").as_bytes());
            let bm = blind_message(&y).unwrap();
            outputs.push((v, bm.blinded_point));
        }

        let sigs = mint.swap(inputs, outputs).unwrap();
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn swap_rejects_value_mismatch() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        let inputs = w.notes.clone();

        let y = hash_to_curve(b"out");
        let bm = blind_message(&y).unwrap();
        let outputs = vec![(2u64, bm.blinded_point)]; // 4 in, 2 out

        assert!(matches!(
            mint.swap(inputs, outputs),
            Err(Error::ValueMismatch { .. })
        ));
    }

    #[test]
    fn swap_does_not_burn_inputs_on_unknown_output_denom() {
        // Mint lacks denom 3. Inputs sum to 3 (1 + 2), outputs request a single
        // value-3 note: value is conserved, but denom 3 is unknown.
        let mint = Mint::new(&[1, 2, 4]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 1).unwrap();
        w.mint_note(&mint, 2).unwrap();
        let inputs = w.notes.clone();

        let y = hash_to_curve(b"out");
        let bm = blind_message(&y).unwrap();
        let outputs = vec![(3u64, bm.blinded_point)];

        assert!(matches!(
            mint.swap(inputs.clone(), outputs),
            Err(Error::UnknownDenomination(3))
        ));

        // Inputs were not spent, since output validation happens first.
        assert!(mint.verify_and_spend(&inputs[0]).is_ok());
        assert!(mint.verify_and_spend(&inputs[1]).is_ok());
    }
}
