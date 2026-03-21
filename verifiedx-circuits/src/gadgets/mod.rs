//! In-circuit gadgets for VerifiedX privacy circuits.
//!
//! These gadgets wrap the `StandardComposer` API to provide
//! reusable building blocks for the privacy circuits.

pub mod poseidon;
pub mod merkle;
pub mod note_hash;
pub mod nullifier;
pub mod range;