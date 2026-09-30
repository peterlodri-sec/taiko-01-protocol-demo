//! Idea 1 — Deterministic preconfirmations via zero-alloc execution gates.
//!
//! A based sequencer / preconfirmation provider validates, gates, and verifies
//! a state-transition request before L1 block inclusion. The hot path is
//! zero-alloc: fixed-size arrays, no heap. Every request is either signed or
//! refused — the gate admits what it can verify and refuses what it cannot.

use crate::{hash, verify_signature, Budget, Hash};

/// A preconfirmation request: a state transition, a monotonic sequence, and a
/// signature over both.
#[derive(Clone, Copy, Debug)]
pub struct PreconfRequest {
    pub state_transition: Hash,
    pub sequence: u64,
    pub signature: [u8; 64],
}

impl PreconfRequest {
    /// The exact 40 bytes signed: `state_transition || sequence` (little-endian).
    pub fn signed_message(&self) -> [u8; 40] {
        let mut message = [0u8; 40];
        message[..32].copy_from_slice(&self.state_transition);
        message[32..].copy_from_slice(&self.sequence.to_le_bytes());
        message
    }
}

/// The gate's verdict: accepted (with the new state root) or refused (why).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateVerdict {
    Accepted { state_root: Hash },
    RefusedBadSignature,
    RefusedNonMonotonic,
    RefusedBudgetExhausted,
}

/// The preconfirmation gate. Zero-alloc hot path: a pinned authority, a
/// monotonic sequence, a no-refunds budget, and a hash-linked ledger head.
pub struct Gate {
    authority: [u8; 32],
    last_sequence: u64,
    budget: Budget,
    head: Hash,
}

pub const BAD_SIGNATURE_COST: u32 = 5;

impl Gate {
    pub fn new(authority: [u8; 32], budget_cap: u32) -> Self {
        Self {
            authority,
            last_sequence: 0,
            budget: Budget::new(budget_cap),
            head: [0u8; 32],
        }
    }

    /// Adjudicate a request: verify, gate, and — if valid — commit to the ledger.
    pub fn adjudicate(&mut self, request: &PreconfRequest) -> GateVerdict {
        // 0. Budget: once the no-refunds budget is exhausted, the gate closes —
        //    no further work, no further charges.
        if self.budget.exhausted() {
            return GateVerdict::RefusedBudgetExhausted;
        }
        // 1. Monotonic sequence: a replayed or out-of-order request is refused.
        if request.sequence <= self.last_sequence {
            return GateVerdict::RefusedNonMonotonic;
        }
        // 2. Signature: a forged or tampered request is refused and charged.
        if !verify_signature(&self.authority, &request.signed_message(), &request.signature) {
            self.budget = self.budget.charge(BAD_SIGNATURE_COST);
            return GateVerdict::RefusedBadSignature;
        }
        // 3. Accept: commit the transition into the hash-verified ledger head.
        let mut commit = [0u8; 64];
        commit[..32].copy_from_slice(&self.head);
        commit[32..].copy_from_slice(&request.state_transition);
        let state_root = hash(&commit);
        self.head = state_root;
        self.last_sequence = request.sequence;
        GateVerdict::Accepted { state_root }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> ([u8; 32], SigningKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        (signing.verifying_key().to_bytes(), signing)
    }

    fn signed_request(signing: &SigningKey, transition: Hash, sequence: u64) -> PreconfRequest {
        let request = PreconfRequest {
            state_transition: transition,
            sequence,
            signature: [0u8; 64],
        };
        let signature = signing.sign(&request.signed_message());
        PreconfRequest {
            signature: signature.to_bytes(),
            ..request
        }
    }

    #[test]
    fn valid_request_is_accepted_and_committed() {
        let (authority, signing) = keypair(1);
        let mut gate = Gate::new(authority, 100);
        let request = signed_request(&signing, [9u8; 32], 1);
        match gate.adjudicate(&request) {
            GateVerdict::Accepted { state_root } => assert_ne!(state_root, [0u8; 32]),
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn tampered_transition_is_refused() {
        let (authority, signing) = keypair(2);
        let mut gate = Gate::new(authority, 100);
        let mut request = signed_request(&signing, [9u8; 32], 1);
        request.state_transition[0] ^= 1; // tamper
        assert_eq!(gate.adjudicate(&request), GateVerdict::RefusedBadSignature);
        assert_eq!(gate.budget.spent(), BAD_SIGNATURE_COST);
    }

    #[test]
    fn replayed_sequence_is_refused() {
        let (authority, signing) = keypair(3);
        let mut gate = Gate::new(authority, 100);
        let first = signed_request(&signing, [1u8; 32], 7);
        assert!(matches!(gate.adjudicate(&first), GateVerdict::Accepted { .. }));
        let replayed = signed_request(&signing, [2u8; 32], 7); // same sequence
        assert_eq!(gate.adjudicate(&replayed), GateVerdict::RefusedNonMonotonic);
    }

    #[test]
    fn exhausted_budget_closes_the_gate() {
        let (authority, _signing) = keypair(4);
        let mut gate = Gate::new(authority, BAD_SIGNATURE_COST * 2);
        let bad = PreconfRequest {
            state_transition: [9u8; 32],
            sequence: 1,
            signature: [0u8; 64],
        };
        // Two bad signatures exhaust the budget (5 + 5 = 10 = cap).
        assert_eq!(gate.adjudicate(&bad), GateVerdict::RefusedBadSignature);
        let bad2 = PreconfRequest { sequence: 2, ..bad };
        assert_eq!(gate.adjudicate(&bad2), GateVerdict::RefusedBadSignature);
        // Now the budget is exhausted: even a correctly sequenced request is
        // refused at the budget gate, not re-examined.
        let any = PreconfRequest { sequence: 3, ..bad };
        assert_eq!(gate.adjudicate(&any), GateVerdict::RefusedBudgetExhausted);
    }
}
