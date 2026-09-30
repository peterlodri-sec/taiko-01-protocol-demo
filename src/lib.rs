//! taiko-01-protocol-demo — 0/1 protocol demos for Taiko.
//!
//! Two end-to-end demos:
//!
//! 1. **Deterministic preconfirmations** ([`preconf`]) — a zero-alloc
//!    execution gate that validates, signs, or refuses a state transition
//!    before it reaches L1.
//! 2. **Capability-gated agent runtime** ([`capability`]) — a hash-verified
//!    execution trace and an integrity notary that anchors a state proof.
//!
//! Honesty first: every gate proves or refuses. Nothing is asserted.
//! `blake3` is the commitment primitive; `ed25519-dalek` is the signature.

pub mod capability;
pub mod preconf;

use ed25519_dalek::{Signature, VerifyingKey};

pub type Hash = [u8; 32];

/// BLAKE3 hash — the single commitment primitive.
pub fn hash(data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Operational budget: zero-alloc, no-refunds, session-local.
/// Measured policy violations, not moral worth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    spent: u32,
    cap: u32,
}

impl Budget {
    pub const fn new(cap: u32) -> Self {
        Self { spent: 0, cap }
    }

    pub const fn spent(self) -> u32 {
        self.spent
    }

    /// Charge a violation. Saturates at the cap; never refunds.
    pub const fn charge(self, cost: u32) -> Self {
        let next = self.spent + cost;
        Self {
            spent: if next > self.cap { self.cap } else { next },
            cap: self.cap,
        }
    }

    pub const fn exhausted(self) -> bool {
        self.spent >= self.cap
    }
}

/// Verify an Ed25519 signature with a pinned public key.
/// Returns `false` on any failure — a bad signature is a refusal, not a panic.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    verifying
        .verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}
