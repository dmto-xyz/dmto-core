use rand::RngCore;
use secp256k1::Secp256k1;

use crate::{hash::hash_to_curve, mint::Mint, types::Note};

pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    pub fn mint_note(&mut self, mint: &Mint, value: u64) {
        let key = mint.keys.get(&value).unwrap();

        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let y = hash_to_curve(&secret);
        let c = y.mul_tweak(&Secp256k1::new(), &key.privkey.into()).unwrap();

        self.notes.push(Note {
            value,
            secret,
            y,
            c,
        });
    }

    pub fn spend(&mut self, mint: &Mint, amount: u64) -> bool {
        let mut selected = Vec::new();
        let mut sum = 0;

        for n in &self.notes {
            if sum >= amount {
                break;
            }
            selected.push(n.clone());
            sum += n.value;
        }

        if sum != amount {
            return false;
        }

        for n in &selected {
            if !mint.verify_and_spend(n) {
                return false;
            }
        }

        self.notes
            .retain(|n| !selected.iter().any(|s| s.secret == n.secret));

        true
    }
}
