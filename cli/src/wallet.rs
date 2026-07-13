//! On-disk wallet: a JSON file of notes, plus denomination/selection helpers.

use std::error::Error;
use std::path::Path;

use dmto_ecash::types::Note;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    /// Load the wallet from `path`, returning an empty wallet if it doesn't exist.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Wallet::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn balance(&self) -> u64 {
        self.notes.iter().map(|n| n.value).sum()
    }
}

/// Break `amount` into available denominations (largest first). Returns `None` if
/// it can't be represented exactly with `denoms`.
pub fn split_amount(mut amount: u64, denoms: &[u64]) -> Option<Vec<u64>> {
    let mut sorted: Vec<u64> = denoms.iter().copied().filter(|&d| d > 0).collect();
    sorted.sort_unstable_by(|a, b| b.cmp(a));

    let mut out = Vec::new();
    for d in sorted {
        while amount >= d {
            out.push(d);
            amount -= d;
        }
    }
    (amount == 0).then_some(out)
}

/// Choose note indices summing exactly to `amount` (greedy, largest first).
/// Returns `None` if no exact selection is possible.
pub fn select_exact(values: &[u64], amount: u64) -> Option<Vec<usize>> {
    let mut order: Vec<usize> = (0..values.len()).collect();
    order.sort_unstable_by(|&a, &b| values[b].cmp(&values[a]));

    let mut remaining = amount;
    let mut chosen = Vec::new();
    for i in order {
        if remaining == 0 {
            break;
        }
        if values[i] <= remaining {
            remaining -= values[i];
            chosen.push(i);
        }
    }
    (remaining == 0).then_some(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENOMS: &[u64] = &[1, 2, 4, 8, 16, 32, 64];

    #[test]
    fn split_powers_of_two() {
        assert_eq!(split_amount(6, DENOMS), Some(vec![4, 2]));
        assert_eq!(split_amount(11, DENOMS), Some(vec![8, 2, 1]));
        assert_eq!(split_amount(0, DENOMS), Some(vec![]));
    }

    #[test]
    fn split_unrepresentable_returns_none() {
        // No denom 1 -> odd amounts can't be formed.
        assert_eq!(split_amount(3, &[2, 4]), None);
    }

    #[test]
    fn select_exact_picks_notes() {
        let values = [4, 2, 1, 8];
        let chosen = select_exact(&values, 6).unwrap();
        let sum: u64 = chosen.iter().map(|&i| values[i]).sum();
        assert_eq!(sum, 6);
    }

    #[test]
    fn select_exact_impossible_returns_none() {
        let values = [4, 4];
        assert_eq!(select_exact(&values, 6), None);
    }
}
