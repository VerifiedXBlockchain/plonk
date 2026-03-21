//! VerifiedX privacy circuits.
//!
//! Each circuit implements the `Circuit` trait from `plonk-core`
//! and is parameterized over the scalar field and curve parameters.

pub mod shield;
pub mod transfer;
pub mod unshield;
pub mod fee;

/// Circuit type identifiers matching `PlonkCircuitType` on the C# side.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitType {
    Transfer = 0,
    Shield = 1,
    Unshield = 2,
    Fee = 3,
}