use rand::RngCore;
use secp256k1::Secp256k1;

use crate::{
    error::{Error, Result},
    hash::hash_to_curve,
    mint::Mint,
    types::Note,
};

pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    /// Mint a new note of `value` directly from the mint (no blinding).
    pub fn mint_note(&mut self, mint: &Mint, value: u64) -> Result<()> {
        let key = mint
            .keys
            .get(&value)
            .ok_or(Error::UnknownDenomination(value))?;

        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let y = hash_to_curve(&secret);
        let c = y.mul_tweak(&Secp256k1::new(), &key.privkey.into())?;

        self.notes.push(Note {
            value,
            secret,
            y,
            c,
        });
        Ok(())
    }

    /// Spend notes summing exactly to `amount`. On success the spent notes are
    /// removed from the wallet.
    pub fn spend(&mut self, mint: &Mint, amount: u64) -> Result<()> {
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
            return Err(Error::SelectionFailed {
                requested: amount,
                selected: sum,
            });
        }

        for n in &selected {
            mint.verify_and_spend(n)?;
        }

        self.notes
            .retain(|n| !selected.iter().any(|s| s.secret == n.secret));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::Mint;

    #[test]
    fn spend_exact_amount_removes_notes() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        w.mint_note(&mint, 2).unwrap();

        assert!(w.spend(&mint, 6).is_ok());
        assert!(w.notes.is_empty());
    }

    #[test]
    fn spend_fails_without_exact_selection() {
        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();

        assert!(matches!(
            w.spend(&mint, 6),
            Err(Error::SelectionFailed {
                requested: 6,
                selected: 4
            })
        ));
    }
}
