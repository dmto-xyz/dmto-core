# dmto — Roadmap

Phased plan from today's prototype toward the network described in
[SPEC.md](./SPEC.md). Each phase has a **goal**, **deliverables**, **exit criteria**,
and the SPEC sections it realizes. Phases are ordered but adjacent ones may overlap.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

**Where we are:** the `dmto-ecash` crate is a working single-process BDHKE ecash demo
(mint, wallet, blind signatures, DLEQ, double-spend prevention, value-conserving swap).
It is in-memory, untested, not serializable, and not networked. The `cli` crate is a
stub. Everything in §3–§4 of the SPEC (multi-issuer economy, relays, postage) is design
only.

---

## Phase 0 — Harden the ecash core ✅

**Goal:** turn the demo into a dependable, tested library with real error handling and a
wire format — the substrate every later phase builds on.

- [x] Split library API from the `main.rs` demo; expose a clean `dmto-ecash` lib crate.
- [x] Replace `.unwrap()` paths with a proper `Error` enum and `Result` returns.
- [x] Add `serde` (de)serialization for `Note`, `BlindedMessage`, and `DLEQ` (wire format).
- [x] Unit tests for `hash_to_curve`, blind/unblind, DLEQ verify (incl. failure cases),
      and mint `verify_and_spend` / `swap` (incl. double-spend and value-mismatch).
- [x] Introduce **keysets** (a mint's set of per-denomination keys with a keyset id).
- [x] CI: `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`.

**Exit criteria:** `cargo test` covers the crypto and mint logic; no `unwrap` in library
paths; notes and proofs round-trip through serde. **Met.**
**SPEC:** §2.

## Phase 1 — Ecash as a service ✅

**Goal:** run a mint as a networked service with persistence and a real client wallet.

- [x] Define the mint API (mint / swap / melt / keyset info) as request/response types.
- [x] Mint server binary (`dmto-relay`): **HTTP** (axum) endpoints for mint / swap / melt /
      keyset. _(WebSocket for real-time delivery arrives with messaging in Phase 3.)_
- [x] Wallet client (`dmto-cli`) that talks to a remote mint over HTTP and stores notes on
      disk (`keyset` / `mint` / `balance` / `list` / `melt`; verifies DLEQ before accepting).
- [x] Persist mint state in **Postgres via sqlx**: keyset (signing keys) so the keyset id
      is stable across restarts, and the spent-secret set (atomic per-request transaction,
      unique-violation → double-spend) so double-spend protection survives restarts.
- [x] **Issuer identity:** stable issuer keypair persisted in Postgres; issuer id published
      at `GET /v1/info` alongside the keyset.
- [x] **Total-supply accounting** per keyset (issued / redeemed / outstanding, per denom),
      published at `GET /v1/supply`.

**Stack:** Postgres + `sqlx`; HTTP by default, WebSocket where real-time is needed (see Decisions).

**Exit criteria:** a wallet on one process mints, swaps, and spends against a mint on
another process, across restarts; total supply is queryable. **Met.**
**SPEC:** §2, §3.1, §3.2.

## Phase 2 — Multi-issuer economy

**Goal:** many independent issuers, cross-issuer exchange, and user-controlled trust.

- [x] Wallet holds notes from **multiple issuers** simultaneously (`dmto-cli` groups notes
      into per-issuer accounts; `mint`/`melt`/`balance` are scoped by the issuer at
      `DMTO_RELAY_URL`).
- [ ] **Trust config:** per-user list of accepted issuers with limits/policies; revocable.
- [ ] **Exchange:** swap issuer-A ecash for issuer-B ecash at a posted/negotiated rate.
- [ ] Exchange/quote endpoint an issuer or server can expose.

**Exit criteria:** a user acquires issuer-B ecash by paying with issuer-A ecash through
an exchange, with the trade honoring the user's trust config.
**SPEC:** §3.1, §3.3, §3.4.

## Phase 3 — Relay transport

**Goal:** a generic store-and-forward relay that carries payloads between users.

- [ ] Message/envelope wire format (sender, recipient, payload, postage slots — see Phase 4).
- [ ] Relay server: accept, route, and **hold messages for offline recipients**.
- [ ] Recipient client: connect, fetch held messages, acknowledge delivery.
- [ ] Optional retention/backup of delivered messages.
- [ ] Keep the payload opaque so the relay is a **generic** transport, not messaging-only.

**Exit criteria:** sender → relay → offline recipient; recipient reconnects and receives;
relay carries an arbitrary payload type.
**SPEC:** §4.1, §4.2, §4.3.

## Phase 4 — Anti-spam postage

**Goal:** ecash-gated sending with two independent, optional postage components.

- [ ] Two postage slots in the envelope: **recipient postage** and **relay postage**.
- [ ] Each slot names **any issuer** the demanding party accepts (no fixed pairing).
- [ ] Postage policy per party (required?, accepted issuer(s), amount, exemptions).
- [ ] Relay verifies/consumes relay postage before routing.
- [ ] Recipient verifies/consumes recipient postage on accept.
- [ ] **Allowlist** exemptions and **refund-on-accept**.

**Exit criteria:** a stranger's message is rejected without valid postage and accepted
with it; an allowlisted sender is exempt; postage can be refunded on accept.
**SPEC:** §4.4, §4.5.

## Phase 5 — Delegation & offline participation

**Goal:** users transact and stay reachable while offline via a chosen delegate.

- [ ] Scoped, revocable delegation grant (which issuers, rate bounds, caps).
- [ ] Delegated **exchange** executed by a server on the user's behalf.
- [ ] Delegated **postage acceptance / posted-price sale** so offline recipients are reachable.

**Exit criteria:** an offline user's delegate completes an exchange and accepts postage
on their behalf within the granted constraints.
**SPEC:** §3.5, §4.5.

## Phase 6 — Messaging app (email 2.0)

**Goal:** an end-to-end messaging experience on the relay + economy layers.

- [ ] Address/identity scheme for users.
- [ ] Client (CLI first) to compose, send, receive, and manage postage/allowlists.
- [ ] End-to-end scenario: two users message each other across relays with postage.
- [ ] Documentation and a quickstart.

**Exit criteria:** two users exchange messages end-to-end with spam protection working.
**SPEC:** §4, §5.

---

## Cross-cutting concerns (all phases)

- **Security:** the crypto is the foundation — reviewed changes, no panics on untrusted
  input, constant-time where it matters, no key material in logs.
- **Privacy:** preserve the blinding guarantees; minimize metadata in envelopes.
- **Docs sync:** as each item ships, move the matching SPEC line from **[target]** to
  **[implemented]** and update the README status table.
- **Testing:** unit tests per module; integration tests per phase exit criterion.

## Decisions

- **Transport:** HTTP (request/response) as the default, WebSocket for real-time
  connections (e.g. live message delivery, notifications).
- **Persistence:** PostgreSQL accessed via `sqlx`.

## Open questions

- Backing of ecash units (abstract units vs. Lightning/on-chain) — currently abstract.
- Exchange rate discovery (posted price vs. order book vs. AMM).
- Identity/addressing scheme for users and issuers.
- HTTP server framework: assuming **axum** unless decided otherwise.
