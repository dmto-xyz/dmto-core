use std::collections::HashMap;

use dashmap::DashSet;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::{
    blind::{DLEQ, blind_sign},
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
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);

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
    pub keys: HashMap<u64, MintKey>,
    pub spent: DashSet<Vec<u8>>,
}

impl Mint {
    pub fn new(denoms: &[u64]) -> Self {
        let keys = denoms.iter().map(|&v| (v, MintKey::new(v))).collect();
        Self {
            keys,
            spent: DashSet::new(),
        }
    }

    pub fn verify_and_spend(&self, note: &Note) -> bool {
        let key = match self.keys.get(&note.value) {
            Some(k) => k,
            None => return false,
        };

        if key.value != note.value {
            return false;
        }

        let expected = note
            .y
            .mul_tweak(&Secp256k1::new(), &key.privkey.into())
            .unwrap();

        if note.c != expected {
            return false;
        }

        if self.spent.contains(&note.secret) {
            return false;
        }

        self.spent.insert(note.secret.clone());
        true
    }

    pub fn swap(
        &self,
        inputs: Vec<Note>,
        outputs: Vec<(u64, PublicKey)>,
    ) -> Option<Vec<(PublicKey, DLEQ)>> {
        let in_sum: u64 = inputs.iter().map(|n| n.value).sum();
        let out_sum: u64 = outputs.iter().map(|(v, _)| *v).sum();

        if in_sum != out_sum {
            return None;
        }

        for n in &inputs {
            if !self.verify_and_spend(n) {
                return None;
            }
        }

        let mut sigs = Vec::new();
        for (value, blinded) in outputs {
            let key = self.keys.get(&value)?;
            sigs.push(blind_sign(&key.privkey, &blinded));
        }

        Some(sigs)
    }
}
