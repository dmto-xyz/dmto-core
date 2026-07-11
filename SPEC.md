# dmto — Specification

## 1. Overview

**dmto** is a decentralized messaging network with a built-in ecash economy. It aims to
be **email 2.0**: an open, federated way to send messages between users, where **ecash
provides spam protection** and doubles as the native value layer of the ecosystem.

Two cooperating layers:

1. **Transport layer** — a network of independent **relay servers** that route and
   store-and-forward messages between users.
2. **Economy layer** — an **ecash economy** in which value can be issued by anyone,
   exchanged across issuers, and spent, without depending on a single central mint.

This document describes both what exists today and the target design. Sections marked
**[implemented]** reflect the current code; sections marked **[target]** are the
intended design and are not built yet.

---

## 2. Current implementation [implemented]

The `dmto-ecash` crate implements a Chaumian ecash primitive using **blind
Diffie–Hellman key exchange (BDHKE)** over secp256k1, following the Cashu scheme.

### 2.1 Primitives

| Concept | Definition |
| ------- | ---------- |
| Mint key | Per-denomination keypair `(x, K = x·G)`. |
| Secret | Random 32-byte value chosen by the wallet. |
| `Y` | `hash_to_curve(secret)` — the message point the mint signs. |
| Note | `{ value, secret, Y, C }` where `C = x·Y` is the mint's signature. |
| Blinding | `B_ = Y + r·G` hides `Y` from the mint using blind factor `r`. |
| Blind signature | `C' = x·B_`, unblinded to `C = C' − r·K`. |
| DLEQ proof | Proof that the mint signed with its advertised key `A`, i.e. `log_G(A) = log_{B_}(C')`. |

### 2.2 Roles

- **Mint** (`mint.rs`): holds one keypair per denomination; `verify_and_spend` checks
  `C == x·Y` and rejects reuse via a spent-secret set; `swap` burns input notes and
  blind-signs new outputs while enforcing that input value equals output value.
- **Wallet** (`wallet.rs`): mints notes and spends them by selecting notes and
  submitting them to the mint.

### 2.3 Properties demonstrated

- **Privacy**: the mint never sees `Y` at signing time (blinding).
- **Verifiability**: DLEQ proofs let wallets confirm which key signed their note.
- **Double-spend prevention**: spent secrets are tracked and re-spends rejected.
- **Value conservation**: swaps require input sum == output sum.

### 2.4 Not yet implemented

- Networking / relay transport, message format, persistence.
- Multiple/independent issuers and cross-issuer exchange.
- Total-supply accounting, delegation, and the trust model below.
- Lightning or on-chain backing; denominations are abstract units.

---

## 3. Target: the ecash economy [target]

The goal is not a single mint but an **ecash economy ecosystem** with many issuers.

### 3.1 Anyone can issue ecash (user-issued ecash)

Ecash is not restricted to relay operators. **Any participant — a user, a community,
an application, or a relay server — can run a mint and issue their own ecash.** Each
issuer's ecash is a distinct asset identified by the issuer's public key.

- Relay-server-issued ecash and user-issued ecash are first-class and interoperate
  through exchange (§3.3).
- Trust in any given issuer's ecash is a **local decision** by each holder (§3.4), not
  a network-wide rule.

### 3.2 Total supply is public

Each issuer publishes verifiable **total-supply information** for the ecash it issues
(amount outstanding, denomination structure, and issuance history/commitments). This
lets holders reason about dilution and an issuer's credibility before accepting or
holding that ecash.

### 3.3 Exchange between issuers

Holders can **exchange one issuer's ecash for another's** — in particular between
relay-server-issued and user-issued ecash. Exchange is a market operation: rates are
set by the parties/servers offering it, not fixed by the protocol. This is what ties
independent issuers into a single economy rather than isolated islands.

### 3.4 User-chosen trust

**The user decides which issuers and which servers to trust and use.** There is no
global authority whitelisting mints. A user maintains their own set of accepted
issuers (with per-issuer limits/policies), and can drop an issuer at any time. Software
should make trust explicit and revocable.

### 3.5 Delegated exchange (offline users)

Because a user is **not always online**, they can **delegate ecash exchange to a chosen
server**. The server performs exchanges on the user's behalf under user-defined
constraints (which issuers, acceptable rates, amount caps), so the user can keep
transacting/receiving value while offline. Delegation is scoped and revocable, and
should minimize what the delegate can do beyond the authorized exchange.

---

## 4. Target: the transport / relay layer [target]

### 4.1 Relay servers

**Relay servers route traffic between messages** — they carry messages between users
across the network. A user connects to one or more relays of their choosing.

### 4.2 Store-and-forward

Relays **hold messages for a recipient who is offline** and deliver them when the
recipient reconnects. A relay may also serve as **message backup/retention** for its
users.

### 4.3 Generic relaying

The relay is **not limited to messaging**. It is intended as a **generic
store-and-forward / relaying mechanism** usable by different applications, with
messaging (email 2.0) as the first application built on top.

### 4.4 Ecash as spam protection

Sending through a relay is **gated by ecash**: a sender attaches ecash (a fee or
proof-of-payment) to have a message routed/held. This makes bulk unsolicited messaging
costly and gives relays a sustainable, spam-resistant economic model. The ecash used
here is drawn from the economy layer (§3), so anti-spam and value transfer share one
system.

---

## 5. Target user cases

1. **Spam-resistant messaging.** Alice emails Bob over dmto. Her client attaches ecash
   the relay requires; strangers pay a small amount to reach Bob, so spam is
   uneconomical while normal correspondence is cheap or refundable.

2. **Receiving while offline.** Bob is offline for days. Relays hold his incoming
   messages (and can retain a backup) and deliver them when he reconnects.

3. **User-issued currency.** A creator or community issues its own ecash (e.g. as
   credits or membership units) and publishes its total supply. Others can hold, spend,
   and evaluate it on its published issuance.

4. **Cross-issuer exchange.** A user holding a relay's ecash exchanges some of it for a
   community's user-issued ecash to spend in that community, at a market rate.

5. **Choosing who to trust.** A user configures their client to accept ecash from a few
   issuers and specific relays, with per-issuer limits, and revokes one that misbehaves
   — a purely local decision.

6. **Delegated exchange while away.** Before going offline, a user delegates exchange to
   a trusted server with constraints (allowed issuers, max rate, caps). The server keeps
   the user's balances usable and rebalanced without the user online.

7. **Relay as generic transport.** A non-messaging app uses dmto relays purely as
   ecash-gated store-and-forward transport for its own payloads.

---

## 6. Design principles

- **No central issuer or authority** — many issuers, local trust.
- **Privacy by default** — Chaumian ecash keeps payment/message metadata minimal.
- **Verifiable** — issuance (total supply) and signatures (DLEQ) are checkable by holders.
- **Economically spam-resistant** — cost, not gatekeeping, controls abuse.
- **Composable transport** — relays are generic infrastructure, messaging is one app.
