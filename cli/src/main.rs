//! dmto-cli: a wallet client for the relay's mint.
//!
//! Commands:
//!   info              show the mint's issuer id and keyset
//!   keyset            fetch and show the mint's keyset
//!   trust [limit]     trust the current issuer (optional balance cap)
//!   trust-id <hex>    trust an issuer by its id (e.g. an exchange destination)
//!   untrust           revoke trust in the current issuer
//!   trusted           list trusted issuers
//!   mint <amount>     mint ecash totaling <amount> from a trusted issuer
//!   balance           show the stored balance, per issuer
//!   list              list stored notes, per issuer
//!   melt <amount>     redeem notes totaling <amount> back to the current issuer
//!   rates             show the relay's hosted issuers and posted exchange rates
//!   exchange <amount> convert <amount> of the current issuer's ecash at the rate
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

use dmto_ecash::api::{BlindSignature, BlindedOutput, ExchangeRequest, MeltRequest, MintRequest};
use dmto_ecash::blind::{BlindedMessage, blind_message, unblind_signature, verify_dleq};
use dmto_ecash::hash::hash_to_curve;
use dmto_ecash::issuer::IssuerId;
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
        "trust-id" => {
            let id_hex = args.next().ok_or("missing <issuer-hex>")?;
            let issuer = IssuerId::from_hex(&id_hex)?;
            let limit = args.next().map(|s| s.parse::<u64>()).transpose()?;
            let mut wallet = Wallet::load(&wallet_path)?;
            wallet.set_trust(issuer, limit);
            wallet.save(&wallet_path)?;
            match limit {
                Some(l) => println!("trusting {issuer} (limit {l})"),
                None => println!("trusting {issuer} (no limit)"),
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

            let (outputs, pending) = blind_outputs(&split)?;
            let resp = client.mint(&MintRequest { outputs })?;
            let notes = finalize_notes(pending, &info.keyset, resp.signatures)?;
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
        "rates" => {
            let r = client.rates()?;
            println!("hosted issuers:");
            for m in &r.mints {
                println!(
                    "  issuer {} keyset {}",
                    short(&m.issuer.to_string()),
                    short(&m.keyset.id.to_string())
                );
            }
            println!("rates (output = input x num/den):");
            for rate in &r.rates {
                println!(
                    "  {} -> {}: {}/{}",
                    short(&rate.from.to_string()),
                    short(&rate.to.to_string()),
                    rate.num,
                    rate.den
                );
            }
        }
        "exchange" => {
            let amount = parse_amount(args.next())?;
            let from_info = client.info()?;
            let from_keyset = from_info.keyset.id;

            let rates = client.rates()?;
            let rate = *rates
                .rates
                .iter()
                .find(|r| r.from == from_keyset)
                .ok_or("this relay posts no rate from its issuer")?;
            if (amount * rate.num) % rate.den != 0 {
                return Err(format!(
                    "amount {amount} not exchangeable at rate {}/{}",
                    rate.num, rate.den
                )
                .into());
            }
            let out_amount = amount * rate.num / rate.den;
            let to_info = rates
                .mints
                .iter()
                .find(|m| m.keyset.id == rate.to)
                .ok_or("destination issuer not advertised")?
                .clone();

            let mut wallet = Wallet::load(&wallet_path)?;

            // Trust gate on the destination issuer (we're acquiring its ecash).
            let policy = wallet
                .trust(&to_info.issuer)
                .cloned()
                .ok_or("destination issuer not trusted; `trust` it (via its relay) first")?;
            let dest_current = wallet
                .account_index(&to_info.issuer)
                .map(|i| wallet.accounts[i].balance())
                .unwrap_or(0);
            if let Some(limit) = policy.limit
                && dest_current + out_amount > limit
            {
                return Err(format!(
                    "would exceed trust limit {limit} on destination (holding {dest_current}, adding {out_amount})"
                )
                .into());
            }

            // Select source notes.
            let src_idx = wallet
                .account_index(&from_info.issuer)
                .ok_or("no notes held for the source issuer")?;
            let values: Vec<u64> = wallet.accounts[src_idx]
                .notes
                .iter()
                .map(|n| n.value)
                .collect();
            let chosen = select_exact(&values, amount).ok_or_else(|| {
                format!(
                    "cannot select {amount} from source (balance {})",
                    wallet.accounts[src_idx].balance()
                )
            })?;
            let inputs: Vec<Note> = chosen
                .iter()
                .map(|&i| wallet.accounts[src_idx].notes[i].clone())
                .collect();

            // Blind the destination outputs and run the exchange.
            let out_denoms: Vec<u64> = to_info.keyset.keys.keys().copied().collect();
            let out_split = split_amount(out_amount, &out_denoms)
                .ok_or("destination amount cannot be represented")?;
            let (outputs, pending) = blind_outputs(&out_split)?;
            let resp = client.exchange(&ExchangeRequest {
                from: from_keyset,
                to: rate.to,
                inputs,
                outputs,
            })?;
            let notes = finalize_notes(pending, &to_info.keyset, resp.signatures)?;

            // Remove source notes, add destination notes.
            let mut chosen = chosen;
            chosen.sort_unstable_by(|a, b| b.cmp(a));
            for i in chosen {
                wallet.accounts[src_idx].notes.remove(i);
            }
            let dest_idx = wallet.upsert_account(&to_info, &url);
            wallet.accounts[dest_idx].notes.extend(notes);
            wallet.save(&wallet_path)?;
            println!(
                "exchanged {amount} ({}) -> {out_amount} ({}); source {} destination {}",
                short(&from_info.issuer.to_string()),
                short(&to_info.issuer.to_string()),
                wallet.accounts[src_idx].balance(),
                wallet.accounts[dest_idx].balance()
            );
        }
        other => {
            eprintln!("unknown command: {other:?}");
            eprintln!(
                "usage: dmto-cli <info|keyset|trust [limit]|untrust|trusted|\
                 mint <amount>|balance|list|melt <amount>|rates|exchange <amount>>"
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

/// An output the wallet blinded and is waiting to have signed.
struct Pending {
    value: u64,
    secret: Vec<u8>,
    blinded: BlindedMessage,
}

/// Blind one output per denomination in `denoms`.
fn blind_outputs(denoms: &[u64]) -> Result<(Vec<BlindedOutput>, Vec<Pending>), Box<dyn Error>> {
    let mut outputs = Vec::with_capacity(denoms.len());
    let mut pending = Vec::with_capacity(denoms.len());
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
    Ok((outputs, pending))
}

/// Verify the mint's DLEQ proofs and unblind the signatures into spendable notes,
/// checking each against `keyset`.
fn finalize_notes(
    pending: Vec<Pending>,
    keyset: &PublicKeyset,
    signatures: Vec<BlindSignature>,
) -> Result<Vec<Note>, Box<dyn Error>> {
    if signatures.len() != pending.len() {
        return Err("mint returned the wrong number of signatures".into());
    }
    let mut notes = Vec::with_capacity(pending.len());
    for (p, sig) in pending.into_iter().zip(signatures) {
        let pubkey = keyset
            .keys
            .get(&p.value)
            .ok_or("keyset is missing a requested denomination")?;
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
