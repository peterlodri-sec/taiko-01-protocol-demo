# taiko-01-protocol-demo

0/1 protocol demos for Taiko — built to show the protocol mechanics, not the
UI. Two end-to-end demos, both in Rust, both anchored on the same principle:
**prove it, don't assert it.**

## Idea 1 — Deterministic preconfirmations via zero-alloc execution gates

A based sequencer / preconfirmation provider validates, gates, and verifies a
state-transition request before L1 inclusion. The hot path is zero-alloc
(fixed-size arrays, no heap), with a `#![no_std]`-shaped design.

- `PreconfRequest` — a state transition, a monotonic sequence, and an Ed25519
  signature over both.
- `Gate::adjudicate` — the execution gate. It refuses a replayed sequence, a
  bad signature (charging the no-refunds budget), or an exhausted budget; and
  it commits an accepted transition into a hash-verified ledger head, emitting
  the new state root.

The narrative: **sub-second preconfirmations, but only for requests the gate
can actually verify.** It admits what it can verify and refuses what it cannot.

## Idea 2 — Capability-gated agent runtime with an integrity notary

A Vaked-style capability executes an off-chain computation, producing a
hash-verified, monotonic trace; the notary anchors the state proof as a
receipt a verifier (a Taiko L2 contract) can check.

- `Capability` — a named permission with a hard step budget.
- `Trace` — a hash-linked, monotonic ledger. Order matters; it is not
  commutative.
- `Notary::execute` — runs the steps within budget, or refuses (never silently
  truncates). `Notary::verify` recomputes the root and checks the receipt.

The narrative: **an autonomous agent runtime whose every step compiles down to
0/1 verifiability on an L2 EVM layer** — bridging the ERC-8004 agent push with
cryptographic protocol verifiability.

## Run

```bash
cargo test   # 7 tests: gates refuse, traces verify, order matters
```

`blake3` is the commitment primitive; `ed25519-dalek` is the signature.

## The pitch

> *"I built this to test how far we can push deterministic, verifiable memory
> bounds at the preconfirmation layer before state ever touches L1 storage."*
