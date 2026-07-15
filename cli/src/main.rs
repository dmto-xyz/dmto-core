//! dmto-cli: a wallet client for the relay's mint.
//!
//! Commands:
//!   info              show the mint's issuer id and keyset
//!   keyset            fetch and show the mint's keyset
//!   trust [limit]     trust the current issuer (optional balance cap)
//!   untrust           revoke trust in the current issuer
//!   trusted           list trusted issuers
//!   mint <amount>     mint ecash totaling <amount> from a trusted issuer
//!   balance           show the stored balance, per issuer
//!   list              list stored notes, per issuer
//!   melt <amount>     redeem notes totaling <amount> back to the current issuer
//!
//! One wallet holds ecash from multiple issuers; the mint at DMTO_RELAY_URL
//! determines which issuer a command acts on. Minting requires the issuer to be
//! trusted (SPEC §3.4).
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
    let client = MintClient::new(url.clone());

    match command.as_str() {
        "info" => {
            let info = client.info()?;
            println!("issuer: {}", info.issuer);
            print_keyset(&info.keyset);
        }
        "keyset" => {
            let ks = client.keyset()?;
            print_keyset(&ks);
        }
        "trust" => {
            let limit = args.next().map(|s| s.parse::<u64>()).transpose()?;
            let info = client.info()?;
            let mut wallet = Wallet::load(&wallet_path)?;
            wallet.set_trust(info.issuer, limit);
            wallet.save(&wallet_path)?;
            match limit {
                Some(l) => println!("trusting {} (limit {l})", info.issuer),
                None => println!("trusting {} (no limit)", info.issuer),
            }
        }
        "untrust" => {
            let info = client.info()?;
            let mut wallet = Wallet::load(&wallet_path)?;
            let revoked = wallet.revoke_trust(&info.issuer);
            wallet.save(&wallet_path)?;
            if revoked {
                println!("revoked trust in {}", info.issuer);
            } else {
                println!("{} was not trusted", info.issuer);
            }
        }
        "trusted" => {
            let wallet = Wallet::load(&wallet_path)?;
            for t in &wallet.trusted {
                match t.limit {
                    Some(l) => println!("{}  limit {l}", t.issuer),
                    None => println!("{}  no limit", t.issuer),
                }
            }
        }
        "mint" => {
            let amount = parse_amount(args.next())?;
            let info = client.info()?;
            let mut wallet = Wallet::load(&wallet_path)?;

            // Trust gate: only mint from trusted issuers, within their limit.
            let policy = wallet
                .trust(&info.issuer)
                .cloned()
                .ok_or("issuer not trusted; run `dmto-cli trust` first")?;
            let current = wallet
                .account_index(&info.issuer)
                .map(|i| wallet.accounts[i].balance())
                .unwrap_or(0);
            if let Some(limit) = policy.limit
                && current + amount > limit
            {
                return Err(format!(
                    "would exceed trust limit {limit} (holding {current}, minting {amount})"
                )
                .into());
            }

            let denoms: Vec<u64> = info.keyset.keys.keys().copied().collect();
            let split = split_amount(amount, &denoms)
                .ok_or("amount cannot be represented with the mint's denominations")?;

            let notes = mint_notes(&client, &info.keyset, &split)?;
            let idx = wallet.upsert_account(&info, &url);
            wallet.accounts[idx].notes.extend(notes);
            wallet.save(&wallet_path)?;
            println!(
                "minted {amount} from {}; balance {}",
                info.issuer,
                wallet.accounts[idx].balance()
            );
        }
        "balance" => {
            let wallet = Wallet::load(&wallet_path)?;
            for a in &wallet.accounts {
                println!(
                    "{}  {}  {}",
                    short(&a.issuer.to_string()),
                    a.url,
                    a.balance()
                );
            }
            println!("total: {}", wallet.balance());
        }
        "list" => {
            let wallet = Wallet::load(&wallet_path)?;
            for a in &wallet.accounts {
                let values: Vec<u64> = a.notes.iter().map(|n| n.value).collect();
                println!(
                    "{} ({}): {values:?} = {}",
                    short(&a.issuer.to_string()),
                    a.url,
                    a.balance()
                );
            }
            println!("total: {}", wallet.balance());
        }
        "melt" => {
            let amount = parse_amount(args.next())?;
            let info = client.info()?;
            let mut wallet = Wallet::load(&wallet_path)?;
            let idx = wallet
                .account_index(&info.issuer)
                .ok_or("no notes held for this issuer")?;

            let values: Vec<u64> = wallet.accounts[idx].notes.iter().map(|n| n.value).collect();
            let chosen = select_exact(&values, amount).ok_or_else(|| {
                format!(
                    "cannot select notes totaling {amount} (balance {})",
                    wallet.accounts[idx].balance()
                )
            })?;

            let inputs: Vec<Note> = chosen
                .iter()
                .map(|&i| wallet.accounts[idx].notes[i].clone())
                .collect();
            let resp = client.melt(&MeltRequest { inputs })?;

            // Remove the melted notes (highest index first to keep indices valid).
            let mut chosen = chosen;
            chosen.sort_unstable_by(|a, b| b.cmp(a));
            for i in chosen {
                wallet.accounts[idx].notes.remove(i);
            }
            wallet.save(&wallet_path)?;
            println!(
                "melted {} from {}; balance {}",
                resp.melted,
                info.issuer,
                wallet.accounts[idx].balance()
            );
        }
        other => {
            eprintln!("unknown command: {other:?}");
            eprintln!(
                "usage: dmto-cli <info|keyset|trust [limit]|untrust|trusted|\
                 mint <amount>|balance|list|melt <amount>>"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

/// First 16 characters of a hex id, for compact display.
fn short(id: &str) -> &str {
    &id[..id.len().min(16)]
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
