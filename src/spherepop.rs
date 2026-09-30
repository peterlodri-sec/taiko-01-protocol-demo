//! The SpherePOP foundational layer.
//!
//! The governing sequence every admissible transition must pass through:
//!
//! ```text
//! POP → REFUSE → BIND → TRANSFORM → VERIFY → COLLAPSE
//! ```
//!
//! The recovery sequence is the other half:
//!
//! ```text
//! DISCOVER → VERIFY → REPLAY → BRANCH → RANK → PROPOSE → BIND ∨ REFUSE
//! ```
//!
//! A plausible branch may be ranked; only a verified branch may be bound.
//! Unobserved is not low-salience. Never manufacture certainty to complete
//! a pattern.

/// A step in the governing sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum Step {
    #[default]
    Pop,
    Refuse,
    Bind,
    Transform,
    Verify,
    Collapse,
}

/// The governing sequence, in order. A gate walks it on every request.
pub const GOVERNING_SEQUENCE: [Step; 6] = [
    Step::Pop,
    Step::Refuse,
    Step::Bind,
    Step::Transform,
    Step::Verify,
    Step::Collapse,
];

/// An observable position in the governing sequence.
///
/// The transformation record: where an operation was refused, or where it
/// completed, is always legible. This is the "loss ledger" of the gate — an
/// omitted or refused span is never silently erased from the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct Walk(pub Step);

impl Walk {
    /// Every walk begins by popping the request from the stream.
    pub const fn start() -> Self {
        Self(Step::Pop)
    }

    /// Advance to the next step in the governing sequence.
    pub const fn next(self) -> Walk {
        match self.0 {
            Step::Pop => Walk(Step::Refuse),
            Step::Refuse => Walk(Step::Bind),
            Step::Bind => Walk(Step::Transform),
            Step::Transform => Walk(Step::Verify),
            Step::Verify => Walk(Step::Collapse),
            Step::Collapse => Walk(Step::Collapse),
        }
    }

    /// The step this walk is currently at.
    pub const fn at(self) -> Step {
        self.0
    }

    pub const fn refused(self) -> bool {
        matches!(self.0, Step::Refuse)
    }

    pub const fn completed(self) -> bool {
        matches!(self.0, Step::Collapse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_traverses_the_governing_sequence_in_order() {
        let mut walk = Walk::start();
        let mut seen = Vec::new();
        while !walk.completed() {
            seen.push(walk.at());
            walk = walk.next();
        }
        seen.push(walk.at());
        assert_eq!(seen, GOVERNING_SEQUENCE.to_vec());
        assert_eq!(GOVERNING_SEQUENCE.len(), 6);
    }

    #[test]
    fn refusal_and_completion_are_legible() {
        assert!(Walk(Step::Refuse).refused());
        assert!(!Walk(Step::Refuse).completed());
        assert!(Walk(Step::Collapse).completed());
        assert!(!Walk(Step::Collapse).refused());
    }
}