//! dmto-cli: a wallet client for the relay's mint.
//!
//! Commands:
//!   keyset            fetch and show the mint's keyset
//!   mint <amount>     mint ecash totaling <amount> and store it
//!   balance           show the stored balance
//!   list              list stored notes
//!   melt <amount>     redeem notes totaling <amount> back to the mint
//!
//! Config via env: DMTO_RELAY_URL (default http://127.0.0.1:3000),
//! DMTO_WALLET (default ./wallet.json).

mod client;
mod wallet;

use std::error::Error;
use std::path::PathBuf;

use dmto_ecash::api::{BlindedOutput, MeltRequest, MintRequest};
use dmto_ecash::blind::{BlindedMessage, blind_message, unblind_signature, verify_dleq};
use dmto_ecash::hash::hash_to_curve;
use dmto_ecash::keyset::PublicKeyset;
use dmto_ecash::types::Note;
use rand::RngCore;

use client::MintClient;
use wallet::{Wallet, select_exact, split_amount};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();

    let url = std::env::var("DMTO_RELAY_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
    let wallet_path =
        PathBuf::from(std::env::var("DMTO_WALLET").unwrap_or_else(|_| "wallet.json".into()));
    let client = MintClient::new(url);

    match command.as_str() {
        "keyset" => {
            let ks = client.keyset()?;
            print_keyset(&ks);
        }
        "mint" => {
            let amount = parse_amount(args.next())?;
            let ks = client.keyset()?;
            let denoms: Vec<u64> = ks.keys.keys().copied().collect();
            let split = split_amount(amount, &denoms)
                .ok_or("amount cannot be represented with the mint's denominations")?;

            let notes = mint_notes(&client, &ks, &split)?;
            let mut wallet = Wallet::load(&wallet_path)?;
            wallet.notes.extend(notes);
            wallet.save(&wallet_path)?;
            println!("minted {amount}; balance {}", wallet.balance());
        }
        "balance" => {
            let wallet = Wallet::load(&wallet_path)?;
            println!("{}", wallet.balance());
        }
        "list" => {
            let wallet = Wallet::load(&wallet_path)?;
            for n in &wallet.notes {
                println!("{}", n.value);
            }
            println!("total: {}", wallet.balance());
        }
        "melt" => {
            let amount = parse_amount(args.next())?;
            let mut wallet = Wallet::load(&wallet_path)?;
            let values: Vec<u64> = wallet.notes.iter().map(|n| n.value).collect();
            let chosen = select_exact(&values, amount).ok_or_else(|| {
                format!(
                    "cannot select notes totaling {amount} (balance {})",
                    wallet.balance()
                )
            })?;

            let inputs: Vec<Note> = chosen.iter().map(|&i| wallet.notes[i].clone()).collect();
            let resp = client.melt(&MeltRequest { inputs })?;

            // Remove the melted notes (highest index first to keep indices valid).
            let mut chosen = chosen;
            chosen.sort_unstable_by(|a, b| b.cmp(a));
            for i in chosen {
                wallet.notes.remove(i);
            }
            wallet.save(&wallet_path)?;
            println!("melted {}; balance {}", resp.melted, wallet.balance());
        }
        other => {
            eprintln!("unknown command: {other:?}");
            eprintln!("usage: dmto-cli <keyset|mint <amount>|balance|list|melt <amount>>");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn parse_amount(arg: Option<String>) -> Result<u64, Box<dyn Error>> {
    let s = arg.ok_or("missing <amount>")?;
    Ok(s.parse()?)
}

fn print_keyset(ks: &PublicKeyset) {
    println!("keyset: {}", ks.id);
    let denoms: Vec<u64> = ks.keys.keys().copied().collect();
    println!("denominations: {denoms:?}");
}

/// Blind each denomination, ask the mint to sign, verify the DLEQ proofs, and
/// unblind into spendable notes.
fn mint_notes(
    client: &MintClient,
    keyset: &PublicKeyset,
    denoms: &[u64],
) -> Result<Vec<Note>, Box<dyn Error>> {
    struct Pending {
        value: u64,
        secret: Vec<u8>,
        blinded: BlindedMessage,
    }

    let mut pending = Vec::with_capacity(denoms.len());
    let mut outputs = Vec::with_capacity(denoms.len());
    for &value in denoms {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let y = hash_to_curve(&secret);
        let blinded = blind_message(&y)?;
        outputs.push(BlindedOutput {
            value,
            blinded_point: blinded.blinded_point,
        });
        pending.push(Pending {
            value,
            secret,
            blinded,
        });
    }

    let resp = client.mint(&MintRequest { outputs })?;
    if resp.signatures.len() != pending.len() {
        return Err("mint returned the wrong number of signatures".into());
    }

    let mut notes = Vec::with_capacity(pending.len());
    for (p, sig) in pending.into_iter().zip(resp.signatures) {
        let pubkey = keyset
            .keys
            .get(&p.value)
            .ok_or("mint keyset is missing a requested denomination")?;
        if !verify_dleq(&p.blinded.blinded_point, &sig.c_prime, pubkey, &sig.dleq) {
            return Err(format!("DLEQ verification failed for {} unit note", p.value).into());
        }
        let c = unblind_signature(&sig.c_prime, &p.blinded.blind_factor, pubkey)?;
        notes.push(Note {
            value: p.value,
            secret: p.secret.clone(),
            y: hash_to_curve(&p.secret),
            c,
        });
    }
    Ok(notes)
}
