# dmto-core

A decentralized messaging network — think **email 2.0** — where **ecash** is used as
built-in spam protection and as the native unit of an open economy layered on top.

The long-term goal is a network of independent **relay servers** that route messages
between users (and hold them until a recipient comes online), combined with an **ecash
economy** where value can be issued, exchanged, and spent without a central issuer.

> **Status: early prototype.** Today the repo contains a working Chaumian ecash
> primitive (`dmto-ecash`) and a placeholder CLI. The relay/messaging layer and the
> multi-issuer economy described in [SPEC.md](./SPEC.md) are not implemented yet.

## Workspace layout

| Crate         | Status      | What it is |
| ------------- | ----------- | ---------- |
| `dmto-ecash`  | library + demo | Cashu-style blind Diffie–Hellman (BDHKE) ecash: mint, wallet, blind signatures, DLEQ proofs, double-spend prevention. Typed `Error`/`Result` API with unit tests. |
| `cli`         | stub        | Placeholder binary (`Hello, world!`) — intended entry point for a node/wallet CLI. |

## What `dmto-ecash` does today

It's a self-contained demo of Chaumian ecash over secp256k1, modeled on the Cashu
BDHKE scheme:

- **`hash.rs`** — `hash_to_curve(secret)`: deterministically maps a secret to a curve point `Y`.
- **`blind.rs`** — blinding (`B_ = Y + rG`), blind signing (`C' = x·B_`) with a **DLEQ
  proof** that the mint used its advertised key, unblinding (`C = C' − rK`), and DLEQ
  verification.
- **`mint.rs`** — a `Mint` holding one keypair per denomination, `verify_and_spend`
  (checks `C == x·Y` and rejects double-spends via a spent-secret set), and `swap`
  (burn input notes, blind-sign new outputs, enforcing value conservation).
- **`wallet.rs`** — a `Wallet` that mints notes and spends them.
- **`types.rs`** — the `Note { value, secret, y, c }` type.
- **`error.rs`** — the crate `Error`/`Result`; library paths return errors instead of panicking.

Run the tests with `cargo test -p dmto-ecash`.

The cryptographic walkthrough lives in [docs/blindsign.md](./docs/blindsign.md).

## Run the demo

```sh
cargo run -p dmto-ecash
```

This runs an end-to-end scenario: Alice mints notes, swaps them to Bob (blinded, with
DLEQ verification), Bob spends, and a double-spend attempt is rejected.

## Where this is going

See **[SPEC.md](./SPEC.md)** for the target architecture: user-issued ecash with
public total-supply info, cross-issuer exchange, user-chosen trust in servers,
delegated (offline) exchange, and relay servers as a generic store-and-forward
transport with ecash-gated anti-spam.
