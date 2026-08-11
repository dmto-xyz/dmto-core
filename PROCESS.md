# dmto — Development Process

How we work on dmto. Keep this short and followed. Pairs with
[ROADMAP.md](./ROADMAP.md) (what/when) and [SPEC.md](./SPEC.md) (design).

## Guiding principles

- **Spec first.** Design lives in SPEC.md, separated into **[implemented]** and
  **[target]**. Change the spec before building something that contradicts it.
- **Small, verifiable steps.** Prefer a working slice with tests over a large unverified
  change. Every roadmap checkbox should be independently demonstrable.
- **Honest status.** README's status table and the SPEC's implemented/target markers must
  reflect reality. Don't mark something done until its exit criterion is met.
- **The crypto is load-bearing.** Treat `dmto-ecash` changes as security-sensitive.

## Repository layout

| Path            | What it is |
| --------------- | ---------- |
| `dmto-ecash/`   | Ecash primitive and (later) mint/wallet library + service. |
| `cli/`          | Client/node CLI (currently a stub). |
| `docs/`         | Design notes (e.g. `blindsign.md`). |
| `SPEC.md`       | Target design and current implementation. |
| `ROADMAP.md`    | Phased plan and status. |
| `PROCESS.md`    | This file. |

New crates are added to the workspace `Cargo.toml` members list.

## Workflow per roadmap item

1. **Pick** the next `[ ]` item in the current phase; mark it `[~]` in ROADMAP.md.
2. **Branch** off `main` (never work directly on `main`; never use worktrees).
3. **Implement** in a small, reviewable change; write tests alongside.
4. **Verify** against the item's intent — run the code/tests, not just typecheck.
5. **Sync docs:** update README status and move any SPEC line from target → implemented.
6. **Mark done:** flip the item to `[x]` in ROADMAP.md when its exit criterion holds.
7. **Commit only when explicitly asked** (see Git below).

## Definition of Done

An item is done when:

- Its behavior is implemented and covered by tests (unit and, at phase boundaries,
  integration tests matching the phase exit criterion).
- `cargo build`, `cargo test`, `cargo clippy`, and `cargo fmt --check` pass.
- No `.unwrap()` / `panic!` on untrusted or network input in library paths.
- Docs (README, SPEC, ROADMAP) are updated to match.

## Testing

- **Unit tests** live next to the code (`#[cfg(test)] mod tests`) — one per module for
  crypto and mint logic, including failure cases (bad DLEQ, double-spend, value mismatch).
- **Integration tests** in `tests/` exercise a full phase scenario end-to-end.
- The `main.rs` demo is a runnable illustration, **not** a substitute for tests.

## Coding conventions

- Rust 2024 edition; format with `cargo fmt`; keep `cargo clippy` clean.
- Return `Result` with a crate `Error` enum; reserve `unwrap`/`expect` for tests and
  provably-infallible cases (with a comment saying why).
- Never log secret keys, blind factors, or note secrets.
- Match the style of surrounding code; keep comments at the existing density.

## Git

Per the repo owner's standing rules:

- **Never commit, push, or open a PR automatically.** Each of these is a separate action
  requiring an explicit request — approval of a plan is not approval to commit.
- **No git worktrees.** Work in the current working tree/branch.
- Branch off `main` for changes; keep the branch focused on one roadmap item where practical.
- End commit messages with the required `Co-Authored-By` trailer when a commit is requested.

## Keeping docs in sync

When an item ships, in the same change:

- Flip its ROADMAP checkbox to `[x]`.
- Update the README **status** table and "What ... does today" section if capabilities changed.
- Move the corresponding SPEC line(s) from **[target]** to **[implemented]**, or refine
  the design if implementation revealed something.

## Decisions and open questions

- Track unresolved design choices in ROADMAP's **Open questions** section.
- When one is resolved, record the decision in SPEC.md (and `docs/` if it needs detail),
  then remove it from Open questions.
