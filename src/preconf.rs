//! Idea 1 — Deterministic preconfirmations via zero-alloc execution gates.
//!
//! A based sequencer / preconfirmation provider validates, gates, and verifies
//! a state-transition request before L1 block inclusion. The hot path is
//! zero-alloc: fixed-size arrays, no heap. Every request walks the SpherePOP
//! governing sequence — it is either signed or refused, and the step where it
//! stopped is always recorded.

use crate::{
    hash, verify_signature,
    spherepop::{Step, Walk},
    Budget, Hash,
};

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
/// monotonic sequence, a no-refunds budget, a hash-linked ledger head, and a
/// `Walk` that records where on the governing sequence it stopped.
pub struct Gate {
    authority: [u8; 32],
    last_sequence: u64,
    budget: Budget,
    head: Hash,
    walk: Walk,
}

pub const BAD_SIGNATURE_COST: u32 = 5;

impl Gate {
    pub fn new(authority: [u8; 32], budget_cap: u32) -> Self {
        Self {
            authority,
            last_sequence: 0,
            budget: Budget::new(budget_cap),
            head: [0u8; 32],
            walk: Walk::start(),
        }
    }

    /// The step the last adjudication stopped at — the transformation record.
    pub fn walk(&self) -> Step {
        self.walk.at()
    }

    /// Adjudicate a request: walk the governing sequence and emit a verdict.
    /// Nothing is asserted; every path ends at a recorded step.
    pub fn adjudicate(&mut self, request: &PreconfRequest) -> GateVerdict {
        // POP — request popped from the stream.
        self.walk = Walk::start();
        // REFUSE — refuse what cannot be verified, before anything binds.
        // The no-refunds budget closes the gate first: an exhausted budget
        // refuses everything without doing further work or further charges.
        if self.budget.exhausted() {
            self.walk = Walk(Step::Refuse);
            return GateVerdict::RefusedBudgetExhausted;
        }
        if request.sequence <= self.last_sequence {
            self.walk = Walk(Step::Refuse);
            return GateVerdict::RefusedNonMonotonic;
        }
        if !verify_signature(&self.authority, &request.signed_message(), &request.signature) {
            self.budget = self.budget.charge(BAD_SIGNATURE_COST);
            self.walk = Walk(Step::Refuse);
            return GateVerdict::RefusedBadSignature;
        }
        // BIND — only a verified request may bind: advance the sequence.
        self.walk = Walk(Step::Bind);
        self.last_sequence = request.sequence;
        // TRANSFORM — apply the transition to the ledger head.
        self.walk = Walk(Step::Transform);
        let mut commit = [0u8; 64];
        commit[..32].copy_from_slice(&self.head);
        commit[32..].copy_from_slice(&request.state_transition);
        let state_root = hash(&commit);
        // VERIFY — the commitment is deterministic: an external verifier
        // recomputes the root from the same inputs (head + transition) and
        // compares. The gate does not assert its own hash back to itself; it
        // hands the commitment over for checking.
        self.walk = Walk(Step::Verify);
        // COLLAPSE — commit the root and emit the verdict.
        self.head = state_root;
        self.walk = Walk(Step::Collapse);
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
        assert_eq!(gate.walk(), Step::Collapse);
    }

    #[test]
    fn tampered_transition_is_refused() {
        let (authority, signing) = keypair(2);
        let mut gate = Gate::new(authority, 100);
        let mut request = signed_request(&signing, [9u8; 32], 1);
        request.state_transition[0] ^= 1; // tamper
        assert_eq!(gate.adjudicate(&request), GateVerdict::RefusedBadSignature);
        assert_eq!(gate.budget.spent(), BAD_SIGNATURE_COST);
        assert_eq!(gate.walk(), Step::Refuse);
    }

    #[test]
    fn replayed_sequence_is_refused() {
        let (authority, signing) = keypair(3);
        let mut gate = Gate::new(authority, 100);
        let first = signed_request(&signing, [1u8; 32], 7);
        assert!(matches!(gate.adjudicate(&first), GateVerdict::Accepted { .. }));
        let replayed = signed_request(&signing, [2u8; 32], 7); // same sequence
        assert_eq!(gate.adjudicate(&replayed), GateVerdict::RefusedNonMonotonic);
        assert_eq!(gate.walk(), Step::Refuse);
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
        assert_eq!(gate.adjudicate(&bad), GateVerdict::RefusedBadSignature);
        let bad2 = PreconfRequest { sequence: 2, ..bad };
        assert_eq!(gate.adjudicate(&bad2), GateVerdict::RefusedBadSignature);
        let any = PreconfRequest { sequence: 3, ..bad };
        assert_eq!(gate.adjudicate(&any), GateVerdict::RefusedBudgetExhausted);
        assert_eq!(gate.walk(), Step::Refuse);
    }
}