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
| `dmto-relay`  | server (early) | axum HTTP server hosting the mint API (`/v1/mint`, `/v1/swap`, `/v1/melt`, `/v1/keyset`), with its keyset persisted in Postgres (sqlx). Message routing comes in later phases. |
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
- **`keyset.rs`** — a `KeysetId` derived deterministically from a mint's public keys, and
  the `PublicKeyset` a wallet fetches and verifies against.
- **`api.rs`** — serde wire types for the mint's HTTP API (`mint` / `swap` / `melt` /
  keyset), and `Mint::process_*` handlers bridging them to the core operations.
- **`wallet.rs`** — a `Wallet` that mints notes and spends them.
- **`types.rs`** — the `Note { value, secret, y, c }` type.
- **`error.rs`** — the crate `Error`/`Result`; library paths return errors instead of panicking.

`Note`, `BlindedMessage`, and `DLEQ` implement `serde` for a wire format (scalars are
encoded as 32-byte big-endian values).

Run the tests with `cargo test -p dmto-ecash`.

The cryptographic walkthrough lives in [docs/blindsign.md](./docs/blindsign.md).

## Run the demo

```sh
cargo run -p dmto-ecash
```

This runs an end-to-end scenario: Alice mints notes, swaps them to Bob (blinded, with
DLEQ verification), Bob spends, and a double-spend attempt is rejected.

## Run the relay server

The relay needs PostgreSQL. Create a database and point `DATABASE_URL` at it (it defaults
to `postgres://$USER@localhost/dmto`):

```sh
createdb dmto
cargo run -p dmto-relay          # migrates, then listens on 0.0.0.0:3000
curl http://127.0.0.1:3000/v1/keyset
```

Override the bind address with `DMTO_RELAY_ADDR=127.0.0.1:3999`. The server exposes the
mint API (`/v1/mint`, `/v1/swap`, `/v1/melt`, `/v1/keyset`). Migrations run automatically
on startup. The **mint keyset is persisted in Postgres**, so the keyset id is stable
across restarts; the spent-secret set moves to Postgres in the next slice, and message
routing after that.

## Where this is going

See **[SPEC.md](./SPEC.md)** for the target architecture: user-issued ecash with
public total-supply info, cross-issuer exchange, user-chosen trust in servers,
delegated (offline) exchange, and relay servers as a generic store-and-forward
transport with ecash-gated anti-spam.
