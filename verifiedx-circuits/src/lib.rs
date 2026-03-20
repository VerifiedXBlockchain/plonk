//! VerifiedX PLONK circuits on **BLS12-381** / **KZG10** (same stack as `plonk-core` tests).
//!
//! ## v0 — PI digest binding (production pipeline, not full privacy yet)
//!
//! The first circuit proves consistency with a single public field element
//! `H = hash(VFXPI1_bytes)` where `hash` is **SHA-256** reduced into `Fr`
//! (`ark_ff::PrimeField::from_le_bytes_mod_order` on the 32-byte digest).
//! This **does not** enforce Pedersen balances, Merkle paths, or spending keys — it only
//! wires end-to-end prove/verify + FFI. Replace with real constraints incrementally.

mod v0_pi_binding;

pub use v0_pi_binding::{
    hash_vfxpi1_to_fr, prove_vfxpi_v0, trusted_setup_v0, verify_vfxpi_v0, VfxPiBindingV0Circuit,
    VfxPlonkParamsBlob, VfxProveError, VfxVerifyError,
};
