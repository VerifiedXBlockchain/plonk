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

// Re-export v0 types for backwards compatibility
pub use v0_pi_binding::{trusted_setup_v0, VfxPlonkParamsBlob, verify_vfxpi_v0, prove_vfxpi_v0};

/// Generate VXPLNK03 params blob with all 4 circuit keys.
///
/// `include_prover_keys`: if true, prover keys are included (larger file, needed for proving).
/// If false, only verifier keys are included (smaller file, sufficient for validators).
pub fn trusted_setup_v1(
    include_prover_keys: bool,
) -> Result<circuit_keys::ParamsBlobV1, Box<dyn std::error::Error>> {
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalSerialize;
    use plonk_core::commitment::KZG10;
    use rand::SeedableRng;

    type PC = KZG10<Bls12_381>;

    // Generate universal params large enough for the biggest circuit (Transfer at 2^15)
    // Deterministic seed for reproducible setup
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5646585F504C4E4B); // "VFX_PLNK" as u64
    let pp = <PC as plonk_core::commitment::HomomorphicCommitment<ark_bls12_381::Fr>>::setup(
        circuit_keys::MAX_CIRCUIT_SIZE,
        None,
        &mut rng,
    ).map_err(|e| format!("KZG setup failed: {:?}", e))?;

    // Compile all circuits
    let keys = circuit_keys::compile_all_circuits(&pp, include_prover_keys)?;

    // Serialize universal params
    let mut pp_bytes = Vec::new();
    pp.serialize(&mut pp_bytes)?;

    // Serialize circuit keys
    let mut shield_vk_bytes = Vec::new();
    keys.shield_vk.serialize(&mut shield_vk_bytes)?;
    let shield_pk_bytes = if let Some(ref pk) = keys.shield_pk {
        let mut b = Vec::new();
        pk.serialize(&mut b)?;
        Some(b)
    } else {
        None
    };

    let mut transfer_vk_bytes = Vec::new();
    keys.transfer_vk.serialize(&mut transfer_vk_bytes)?;
    let transfer_pk_bytes = if let Some(ref pk) = keys.transfer_pk {
        let mut b = Vec::new();
        pk.serialize(&mut b)?;
        Some(b)
    } else {
        None
    };

    let mut unshield_vk_bytes = Vec::new();
    keys.unshield_vk.serialize(&mut unshield_vk_bytes)?;
    let unshield_pk_bytes = if let Some(ref pk) = keys.unshield_pk {
        let mut b = Vec::new();
        pk.serialize(&mut b)?;
        Some(b)
    } else {
        None
    };

    let mut fee_vk_bytes = Vec::new();
    keys.fee_vk.serialize(&mut fee_vk_bytes)?;
    let fee_pk_bytes = if let Some(ref pk) = keys.fee_pk {
        let mut b = Vec::new();
        pk.serialize(&mut b)?;
        Some(b)
    } else {
        None
    };

    Ok(circuit_keys::ParamsBlobV1 {
        universal_params: pp_bytes,
        shield_vk: shield_vk_bytes,
        shield_pk: shield_pk_bytes,
        transfer_vk: transfer_vk_bytes,
        transfer_pk: transfer_pk_bytes,
        unshield_vk: unshield_vk_bytes,
        unshield_pk: unshield_pk_bytes,
        fee_vk: fee_vk_bytes,
        fee_pk: fee_pk_bytes,
    })
}
