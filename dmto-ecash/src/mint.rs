use std::collections::{BTreeMap, HashMap};

use dashmap::DashSet;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::{
    api::{
        BlindSignature, BlindedOutput, MeltRequest, MeltResponse, MintRequest, SignatureResponse,
        SwapRequest,
    },
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

        self.sign_outputs(&outputs)
    }

    /// Blind-sign each `(value, blinded_point)` output. Fails without signing any
    /// output if a denomination is unknown.
    fn sign_outputs(&self, outputs: &[(u64, PublicKey)]) -> Result<Vec<(PublicKey, DLEQ)>> {
        let mut sigs = Vec::with_capacity(outputs.len());
        for (value, blinded) in outputs {
            let key = self
                .keys
                .get(value)
                .ok_or(Error::UnknownDenomination(*value))?;
            sigs.push(blind_sign(&key.privkey, blinded)?);
        }
        Ok(sigs)
    }

    // --- API handlers (bridge wire types to core operations) ---

    /// Handle a `POST /v1/mint`: issue ecash by blind-signing the outputs.
    pub fn process_mint(&self, req: MintRequest) -> Result<SignatureResponse> {
        let sigs = self.sign_outputs(&to_pairs(&req.outputs))?;
        Ok(build_response(&req.outputs, sigs))
    }

    /// Handle a `POST /v1/swap`: burn inputs and blind-sign equal-value outputs.
    pub fn process_swap(&self, req: SwapRequest) -> Result<SignatureResponse> {
        let sigs = self.swap(req.inputs, to_pairs(&req.outputs))?;
        Ok(build_response(&req.outputs, sigs))
    }

    /// Handle a `POST /v1/melt`: redeem notes back to the mint.
    pub fn process_melt(&self, req: MeltRequest) -> Result<MeltResponse> {
        for n in &req.inputs {
            self.verify_and_spend(n)?;
        }
        let melted = req.inputs.iter().map(|n| n.value).sum();
        Ok(MeltResponse { melted })
    }
}

fn to_pairs(outputs: &[BlindedOutput]) -> Vec<(u64, PublicKey)> {
    outputs.iter().map(|o| (o.value, o.blinded_point)).collect()
}

fn build_response(outputs: &[BlindedOutput], sigs: Vec<(PublicKey, DLEQ)>) -> SignatureResponse {
    let signatures = outputs
        .iter()
        .zip(sigs)
        .map(|(o, (c_prime, dleq))| BlindSignature {
            value: o.value,
            c_prime,
            dleq,
        })
        .collect();
    SignatureResponse { signatures }
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

    #[test]
    fn process_swap_produces_verifiable_signatures() {
        use crate::api::{BlindedOutput, SwapRequest};
        use crate::blind::{unblind_signature, verify_dleq};

        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        w.mint_note(&mint, 2).unwrap();
        let inputs = w.notes.clone();

        // Build a blinded output of value 6 -> split into 4 + 2.
        let mut outputs = vec![];
        let mut blinds = vec![];
        for v in [4u64, 2u64] {
            let y = hash_to_curve(format!("out{v}").as_bytes());
            let bm = blind_message(&y).unwrap();
            outputs.push(BlindedOutput {
                value: v,
                blinded_point: bm.blinded_point,
            });
            blinds.push(bm.blind_factor);
        }

        let resp = mint
            .process_swap(SwapRequest {
                inputs,
                outputs: outputs.clone(),
            })
            .unwrap();
        assert_eq!(resp.signatures.len(), 2);

        // Each returned blind signature verifies and unblinds against the keyset.
        for (i, sig) in resp.signatures.iter().enumerate() {
            let pubkey = mint.keys.get(&sig.value).unwrap().pubkey;
            assert!(verify_dleq(
                &outputs[i].blinded_point,
                &sig.c_prime,
                &pubkey,
                &sig.dleq
            ));
            let _c = unblind_signature(&sig.c_prime, &blinds[i], &pubkey).unwrap();
        }
    }

    #[test]
    fn process_melt_burns_inputs_and_reports_total() {
        use crate::api::MeltRequest;

        let mint = Mint::new(&[1, 2, 4, 8]);
        let mut w = Wallet { notes: vec![] };
        w.mint_note(&mint, 4).unwrap();
        w.mint_note(&mint, 2).unwrap();
        let inputs = w.notes.clone();

        let resp = mint
            .process_melt(MeltRequest {
                inputs: inputs.clone(),
            })
            .unwrap();
        assert_eq!(resp.melted, 6);

        // Re-melting the same notes is rejected as a double-spend.
        assert!(matches!(
            mint.process_melt(MeltRequest { inputs }),
            Err(Error::DoubleSpend)
        ));
    }
}
