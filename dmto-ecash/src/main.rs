use std::collections::HashMap;

use dashmap::DashSet;
use rand::RngCore;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn hash_secret(secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret);
    h.finalize().into()
}

#[derive(Clone)]
pub struct MintKey {
    pub value: u64,
    pub keypair: Keypair,
}

impl MintKey {
    pub fn new(value: u64) -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        Self { value, keypair }
    }

    // pub fn public_key(&self) -> PublicKey {
    //     self.keypair.public_key()
    // }

    pub fn xonly_public_key(&self) -> XOnlyPublicKey {
        let (xonly, _parity) = self.keypair.x_only_public_key();
        xonly
    }
}

pub struct BlindedMessage {
    pub blinded: Message,
    pub blind_factor: [u8; 32],
}

pub fn blind_message(msg: &[u8; 32]) -> BlindedMessage {
    let secp = Secp256k1::new();

    let mut r = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut r);

    let mut blinded = *msg;
    for i in 0..32 {
        blinded[i] ^= r.as_ref()[i];
    }

    BlindedMessage {
        blinded: Message::from_digest(blinded),
        blind_factor: r,
    }
}

pub fn blind_sign(keypair: &Keypair, blinded_msg: &Message) -> Signature {
    let secp = Secp256k1::new();
    secp.sign_schnorr_no_aux_rand(blinded_msg, keypair)
}

pub fn unblind_signature(sig: Signature, _blind_factor: &[u8; 32]) -> Signature {
    // For XOR demo scheme: no-op
    sig
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub value: u64,
    pub secret: [u8; 32],
    pub signature: Signature,
}

pub struct Mint {
    pub keys: HashMap<u64, MintKey>,
    pub spent: DashSet<[u8; 32]>,
}

impl Mint {
    pub fn new(denoms: &[u64]) -> Self {
        let keys = denoms.iter().map(|&v| (v, MintKey::new(v))).collect();

        Self {
            keys,
            spent: DashSet::new(),
        }
    }
}

impl Mint {
    pub fn verify_and_spend(&self, note: &Note) -> bool {
        let key = match self.keys.get(&note.value) {
            Some(k) => k,
            None => return false,
        };

        let h = hash_secret(&note.secret);
        let msg = Message::from_digest(h);

        let secp = Secp256k1::new();
        if secp
            .verify_schnorr(&note.signature, &msg, &key.xonly_public_key())
            .is_err()
        {
            return false;
        }

        if self.spent.contains(&h) {
            return false;
        }

        self.spent.insert(h);
        true
    }
}

pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    pub fn mint_note(&mut self, mint: &Mint, value: u64) {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let msg = hash_secret(&secret);
        let blinded = blind_message(&msg);

        let key = mint.keys.get(&value).unwrap();
        let blind_sig = blind_sign(&key.keypair, &blinded.blinded);
        let sig = unblind_signature(blind_sig, &blinded.blind_factor);

        self.notes.push(Note {
            value,
            secret,
            signature: sig,
        });
    }
}

impl Wallet {
    pub fn spend(&mut self, mint: &Mint, amount: u64) -> bool {
        let mut selected = vec![];
        let mut sum = 0;

        for note in &self.notes {
            if sum >= amount {
                break;
            }
            selected.push(note.clone());
            sum += note.value;
        }

        if sum != amount {
            return false;
        }

        for note in &selected {
            if !mint.verify_and_spend(note) {
                return false;
            }
        }

        self.notes.retain(|n| !selected.contains(n));
        true
    }
}

impl Mint {
    pub fn swap(&self, inputs: Vec<Note>, outputs: Vec<(u64, Message)>) -> Option<Vec<Signature>> {
        let total_in: u64 = inputs.iter().map(|n| n.value).sum();
        let total_out: u64 = outputs.iter().map(|(v, _)| *v).sum();

        if total_in != total_out {
            return None;
        }

        for note in &inputs {
            if !self.verify_and_spend(note) {
                return None;
            }
        }

        let mut sigs = vec![];
        for (value, msg) in outputs {
            let key = self.keys.get(&value)?;
            sigs.push(blind_sign(&key.keypair, &msg));
        }

        Some(sigs)
    }
}

fn main() {
    println!("=== Chaumian Ecash Demo ===");

    // --------------------------------------------------
    // 1. Initialize mint with denominations
    // --------------------------------------------------
    let denoms = vec![1, 2, 4, 8];
    let mint = Mint::new(&denoms);

    println!("Mint initialized with denoms: {:?}", denoms);

    // --------------------------------------------------
    // 2. Alice mints ecash
    // --------------------------------------------------
    let mut alice = Wallet { notes: vec![] };

    alice.mint_note(&mint, 4);
    alice.mint_note(&mint, 2);

    println!("Alice minted ecash:");
    for n in &alice.notes {
        println!("  - {} unit note", n.value);
    }

    // --------------------------------------------------
    // 3. Bob prepares blinded outputs (for swap)
    // --------------------------------------------------
    let mut bob = Wallet { notes: vec![] };

    let mut blinded_outputs = vec![];
    let mut bob_blinds = vec![];
    let mut bob_secrets = vec![];

    for value in [4u64, 2u64] {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let msg = hash_secret(&secret);
        let blinded = blind_message(&msg);

        blinded_outputs.push((value, blinded.blinded));
        bob_blinds.push(blinded.blind_factor);
        bob_secrets.push(secret);
    }

    // --------------------------------------------------
    // 4. Mint performs swap (Alice → Bob)
    // --------------------------------------------------
    let swap_sigs = mint
        .swap(alice.notes.clone(), blinded_outputs)
        .expect("swap failed");

    println!("Swap successful, mint reissued notes");

    // --------------------------------------------------
    // 5. Bob unblinds and stores fresh notes
    // --------------------------------------------------
    let values = vec![4u64, 2u64];

    for i in 0..values.len() {
        let value = values[i];
        let sig = unblind_signature(swap_sigs[i], &bob_blinds[i]);

        bob.notes.push(Note {
            value,
            secret: bob_secrets[i],
            signature: sig,
        });
    }

    alice.notes.clear();

    println!("Bob received ecash:");
    for n in &bob.notes {
        println!("  - {} unit note", n.value);
    }

    // --------------------------------------------------
    // 6. Bob spends ecash
    // --------------------------------------------------
    let ok = bob.spend(&mint, 6);
    println!("Bob spend result: {}", ok);
    assert!(ok);

    // --------------------------------------------------
    // 7. Double-spend attempt (should fail)
    // --------------------------------------------------
    println!("Attempting double spend...");

    let double_spend = bob.spend(&mint, 6);
    println!("Double spend result: {}", double_spend);
    assert!(!double_spend);

    println!("=== Demo completed successfully ===");
}
