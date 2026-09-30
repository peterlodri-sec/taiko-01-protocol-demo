//! Idea 2 — Capability-gated agent runtime with an integrity notary.
//!
//! A Vaked-style capability graph executes an off-chain computation, producing
//! a hash-verified, monotonic trace; the notary anchors the state proof as a
//! receipt that a verifier (Taiko L2 contract) can check. Bounded by an
//! explicit step budget: exceed it and the execution is refused, not silently
//! truncated.

use crate::{hash, Hash};

/// A capability: a named permission with a hard step budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub id: Hash,
    pub step_budget: u32,
}

/// A hash-linked, monotonic execution trace. Zero-alloc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Trace {
    head: Hash,
    steps: u32,
}

impl Trace {
    pub fn new(seed: Hash) -> Self {
        Self { head: seed, steps: 0 }
    }

    pub fn head(self) -> Hash {
        self.head
    }

    pub fn steps(self) -> u32 {
        self.steps
    }

    /// Append a step: `head = hash(head || step)`. Order matters; the trace is
    /// not commutative — a reordered computation yields a different root.
    pub fn append(&mut self, step: &Hash) {
        let mut commit = [0u8; 64];
        commit[..32].copy_from_slice(&self.head);
        commit[32..].copy_from_slice(step);
        self.head = hash(&commit);
        self.steps += 1;
    }
}

/// The notary's receipt: a commitment to the executed trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub execution_hash: Hash,
    pub steps_used: u32,
}

/// The notary. Executes a capability-gated program and emits a receipt, or
/// refuses when the budget is exceeded. The receipt is a state proof — a
/// verifier can recompute the trace root and check it against the commitment.
pub struct Notary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotaryError {
    BudgetExceeded,
}

impl Notary {
    /// Execute `steps` under `capability`, starting from a `seed` (the initial
    /// state root). Refuses if the step count exceeds the capability budget.
    pub fn execute(
        capability: &Capability,
        seed: Hash,
        steps: &[Hash],
    ) -> Result<Receipt, NotaryError> {
        if steps.len() as u32 > capability.step_budget {
            return Err(NotaryError::BudgetExceeded);
        }
        let mut trace = Trace::new(seed);
        for step in steps {
            trace.append(step);
        }
        Ok(Receipt {
            execution_hash: trace.head(),
            steps_used: trace.steps(),
        })
    }

    /// Verify a receipt against the same capability, seed, and steps: recompute
    /// the trace root and compare. This is what a verifier contract would run.
    pub fn verify(
        capability: &Capability,
        seed: Hash,
        steps: &[Hash],
        receipt: &Receipt,
    ) -> bool {
        Notary::execute(capability, seed, steps)
            .map(|expected| expected == *receipt)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_within_budget_yields_a_verifiable_receipt() {
        let capability = Capability {
            id: [1u8; 32],
            step_budget: 4,
        };
        let steps = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let receipt = Notary::execute(&capability, [0u8; 32], &steps).unwrap();
        assert_eq!(receipt.steps_used, 3);
        assert!(Notary::verify(&capability, [0u8; 32], &steps, &receipt));
    }

    #[test]
    fn exceeding_the_budget_is_refused_not_truncated() {
        let capability = Capability {
            id: [1u8; 32],
            step_budget: 2,
        };
        let steps = [[1u8; 32], [2u8; 32], [3u8; 32]];
        assert_eq!(
            Notary::execute(&capability, [0u8; 32], &steps),
            Err(NotaryError::BudgetExceeded)
        );
    }

    #[test]
    fn trace_order_matters_and_is_not_commutative() {
        let capability = Capability {
            id: [1u8; 32],
            step_budget: 4,
        };
        let forward = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let backward = [[3u8; 32], [2u8; 32], [1u8; 32]];
        let a = Notary::execute(&capability, [0u8; 32], &forward).unwrap();
        let b = Notary::execute(&capability, [0u8; 32], &backward).unwrap();
        assert_ne!(a.execution_hash, b.execution_hash);
    }
}
