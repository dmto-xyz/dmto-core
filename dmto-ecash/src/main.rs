use std::collections::HashMap;

use dashmap::DashSet;
use rand::RngCore;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

fn hash_to_curve(secret: &[u8]) -> PublicKey {
    let secp = Secp256k1::new();
    let mut ctr = 0u32;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"cashu_hash_to_curve");
        hasher.update(secret);
        hasher.update(ctr.to_be_bytes());
        let hash = hasher.finalize();

        if let Ok(sk) = SecretKey::from_slice(&hash) {
            return PublicKey::from_secret_key(&secp, &sk);
        }
        ctr += 1;
    }
}

#[derive(Clone)]
pub struct MintKey {
    pub value: u64,
    pub privkey: SecretKey,
    pub pubkey: PublicKey,
}

impl MintKey {
    pub fn new(value: u64) -> Self {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let privkey = SecretKey::from_slice(&sk_bytes).expect("valid secret key");
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);
        Self {
            value,
            privkey,
            pubkey,
        }
    }

    pub fn xonly_pubkey(&self) -> XOnlyPublicKey {
        let (xonly, _) = self.pubkey.x_only_public_key();
        xonly
    }
}

pub struct BlindedMessage {
    pub blinded_point: PublicKey, // B_ = Y + r*G
    pub blind_factor: Scalar,     // r
}

fn random_scalar() -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(s) = Scalar::from_be_bytes(bytes) {
            if s != Scalar::ZERO {
                return s;
            }
        }
    }
}

pub fn blind_message(y: &PublicKey) -> BlindedMessage {
    let secp = Secp256k1::new();
    let r = random_scalar();

    let r_g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&r.to_be_bytes()).unwrap());
    let blinded_point = y.combine(&r_g).unwrap();

    BlindedMessage {
        blinded_point,
        blind_factor: r,
    }
}

// Mint blindly signs: C' = privkey * B_
pub fn blind_sign(privkey: &SecretKey, blinded_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(privkey.secret_bytes()).unwrap();
    blinded_point.mul_tweak(&secp, &scalar).unwrap()
}

// User unblinds: C = C' - r * K (where K is mint's pubkey)
pub fn unblind_signature(
    blind_sig: &PublicKey,
    blind_factor: &Scalar,
    mint_pubkey: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let r_k = mint_pubkey.mul_tweak(&secp, blind_factor).unwrap();

    blind_sig.combine(&r_k.negate(&secp)).unwrap()
}

#[derive(Clone)]
pub struct Note {
    pub value: u64,
    pub secret: Vec<u8>, // random string (UTF-8)
    pub y: PublicKey,    // Y = hash_to_curve(secret)
    pub c: PublicKey,    // C = privkey * Y
}

pub struct Mint {
    pub keys: HashMap<u64, MintKey>,
    pub spent: DashSet<Vec<u8>>, // spent secrets
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

        // Check signature: C == pubkey * Y
        let expected_c = note
            .y
            .mul_tweak(&Secp256k1::new(), &key.privkey.into())
            .unwrap();
        if note.c != expected_c {
            return false;
        }

        // Prevent double-spend
        if self.spent.contains(&note.secret) {
            return false;
        }
        self.spent.insert(note.secret.clone());
        true
    }

    pub fn swap(
        &self,
        inputs: Vec<Note>,
        outputs: Vec<(u64, PublicKey)>, // blinded points B_
    ) -> Option<Vec<PublicKey>> {
        let total_in: u64 = inputs.iter().map(|n| n.value).sum();
        let total_out: u64 = outputs.iter().map(|(v, _)| *v).sum();

        if total_in != total_out {
            return None;
        }

        // Spend inputs
        for note in &inputs {
            if !self.verify_and_spend(note) {
                return None;
            }
        }

        // Blindly sign outputs
        let mut blind_sigs = Vec::new();
        for (value, blinded_point) in outputs {
            let key = self.keys.get(&value)?;
            let c_prime = blind_sign(&key.privkey, &blinded_point);
            blind_sigs.push(c_prime);
        }
        Some(blind_sigs)
    }
}

pub struct Wallet {
    pub notes: Vec<Note>,
}

impl Wallet {
    // Initial minting: direct issuance (no blinding needed)
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
        // Simple exact match selection
        let mut selected = Vec::new();
        let mut sum = 0u64;

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

        self.notes
            .retain(|n| !selected.iter().any(|s| s.secret == n.secret));

        true
    }
}

fn main() {
    println!("=== Real Chaumian Ecash Demo (Blind-DH / Cashu-style) ===");

    let denoms = vec![1, 2, 4, 8];
    let mint = Mint::new(&denoms);
    println!("Mint initialized with denoms: {:?}", denoms);

    // Alice mints ecash (direct issuance)
    let mut alice = Wallet { notes: vec![] };
    alice.mint_note(&mint, 4);
    alice.mint_note(&mint, 2);
    println!("Alice minted ecash:");
    for n in &alice.notes {
        println!(" - {} unit note", n.value);
    }

    // Bob prepares blinded outputs for swap
    let mut bob = Wallet { notes: vec![] };
    let mut blinded_outputs = vec![];
    let mut bob_blinds = vec![];
    let mut bob_secrets = vec![];

    for value in [4u64, 2u64] {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let y = hash_to_curve(&secret);
        let blinded = blind_message(&y);

        blinded_outputs.push((value, blinded.blinded_point));
        bob_blinds.push(blinded.blind_factor);
        bob_secrets.push(secret);
    }

    // Mint performs swap: burns Alice's notes, blindly signs Bob's
    let blind_sigs = mint
        .swap(alice.notes.clone(), blinded_outputs)
        .expect("swap failed");

    println!("Swap successful, mint reissued notes");

    // Bob unblinds and stores new notes
    let values = vec![4u64, 2u64];
    for i in 0..values.len() {
        let value = values[i];
        let key = mint.keys.get(&value).unwrap();

        let c = unblind_signature(&blind_sigs[i], &bob_blinds[i], &key.pubkey);

        let y = hash_to_curve(&bob_secrets[i]);

        bob.notes.push(Note {
            value,
            secret: bob_secrets[i].clone(),
            y,
            c,
        });
    }
    alice.notes.clear();

    println!("Bob received ecash:");
    for n in &bob.notes {
        println!(" - {} unit note", n.value);
    }

    // Bob spends
    let ok = bob.spend(&mint, 6);
    println!("Bob spend result: {}", ok);
    assert!(ok);

    // Double-spend attempt
    println!("Attempting double spend...");
    let double_spend = bob.spend(&mint, 6);
    println!("Double spend result: {}", double_spend);
    assert!(!double_spend);

    println!("=== Demo completed successfully ===");
}
