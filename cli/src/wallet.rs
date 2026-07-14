//! On-disk wallet. Notes are grouped into per-issuer accounts, so one wallet can
//! hold ecash from multiple issuers at once (SPEC §3.1). Also holds the
//! denomination/selection helpers.

use std::error::Error;
use std::path::Path;

use dmto_ecash::api::MintInfo;
use dmto_ecash::issuer::IssuerId;
use dmto_ecash::keyset::KeysetId;
use dmto_ecash::types::Note;
use serde::{Deserialize, Serialize};

/// Notes held from a single issuer, plus where to reach it.
#[derive(Serialize, Deserialize)]
pub struct Account {
    pub url: String,
    pub issuer: IssuerId,
    pub keyset: KeysetId,
    pub notes: Vec<Note>,
}

impl Account {
    pub fn balance(&self) -> u64 {
        self.notes.iter().map(|n| n.value).sum()
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Wallet {
    pub accounts: Vec<Account>,
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

    /// Total balance across all issuers.
    pub fn balance(&self) -> u64 {
        self.accounts.iter().map(|a| a.balance()).sum()
    }

    pub fn account_index(&self, issuer: &IssuerId) -> Option<usize> {
        self.accounts.iter().position(|a| &a.issuer == issuer)
    }

    /// Find the account for `info`'s issuer, creating it if new. Returns its index
    /// and refreshes the stored url/keyset.
    pub fn upsert_account(&mut self, info: &MintInfo, url: &str) -> usize {
        if let Some(i) = self.account_index(&info.issuer) {
            self.accounts[i].url = url.to_string();
            self.accounts[i].keyset = info.keyset.id;
            i
        } else {
            self.accounts.push(Account {
                url: url.to_string(),
                issuer: info.issuer,
                keyset: info.keyset.id,
                notes: Vec::new(),
            });
            self.accounts.len() - 1
        }
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
    use std::collections::BTreeMap;

    use dmto_ecash::keyset::PublicKeyset;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    const DENOMS: &[u64] = &[1, 2, 4, 8, 16, 32, 64];

    fn fake_info(seed: u8) -> MintInfo {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut keys = BTreeMap::new();
        keys.insert(1u64, pk);
        let keyset = PublicKeyset {
            id: KeysetId::derive(&keys),
            keys,
        };
        MintInfo {
            issuer: IssuerId::new(pk),
            keyset,
        }
    }

    #[test]
    fn split_powers_of_two() {
        assert_eq!(split_amount(6, DENOMS), Some(vec![4, 2]));
        assert_eq!(split_amount(11, DENOMS), Some(vec![8, 2, 1]));
        assert_eq!(split_amount(0, DENOMS), Some(vec![]));
    }

    #[test]
    fn split_unrepresentable_returns_none() {
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
        assert_eq!(select_exact(&[4, 4], 6), None);
    }

    #[test]
    fn upsert_account_is_idempotent_per_issuer() {
        let mut w = Wallet::default();
        let a = fake_info(1);
        let b = fake_info(2);

        let i1 = w.upsert_account(&a, "http://a");
        let i2 = w.upsert_account(&b, "http://b");
        let i1_again = w.upsert_account(&a, "http://a2");

        assert_eq!(i1, i1_again);
        assert_ne!(i1, i2);
        assert_eq!(w.accounts.len(), 2);
        // url refreshed on the existing account
        assert_eq!(w.accounts[i1].url, "http://a2");
    }
}
