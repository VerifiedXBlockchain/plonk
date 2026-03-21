//! VerifiedX privacy circuits for the PLONK proving system.
//!
//! This crate provides:
//! - **Gadgets**: Reusable in-circuit building blocks (Poseidon hash,
//!   Merkle path verification, note hash, nullifier derivation, range proofs)
//! - **Circuits**: Complete privacy circuits implementing the `Circuit` trait
//!   (Shield, Transfer, Unshield, Fee)
//!
//! # Architecture
//!
//! The circuits use a Poseidon note hash as the Merkle leaf to bind
//! amounts to commitments in-circuit, preventing inflation attacks.
//! G1 Pedersen commitments remain for external verification and
//! homomorphic auditing.
//!
//! ```text
//! note_hash = Poseidon(amount_scaled, randomness)   // Merkle leaf
//! nullifier = Poseidon(viewing_key, note_hash, pos) // Spend authorization
//! ```

pub mod gadgets;
pub mod circuits;
pub mod circuit_keys;
pub mod v0_pi_binding;

/// Amount scaling factor: 10^18 (matches C# `AmountConverter.SCALING_FACTOR`).
pub const SCALING_FACTOR: u128 = 1_000_000_000_000_000_000;

/// Scale a decimal amount to a circuit-ready integer.
pub fn scale_amount(amount_decimal: f64) -> u128 {
    (amount_decimal * SCALING_FACTOR as f64) as u128
}