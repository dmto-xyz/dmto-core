use rand::RngCore;

use crate::{
    blind::{blind_message, unblind_signature},
    hash::hash_to_curve,
    mint::Mint,
    types::Note,
    wallet::Wallet,
};

mod blind;
mod hash;
mod mint;
mod types;
mod wallet;

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
