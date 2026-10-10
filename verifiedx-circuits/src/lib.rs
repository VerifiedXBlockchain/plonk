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
pub mod zcash_setup;

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
type KZG10<E> = plonk_core::commitment::KZG10<E>;

/// **INSECURE: for tests only.** The universal parameters are generated from a constant seed, so tau is public and any
/// statement can be proven. Blobs from here are written with magic `VXPLNK04`, which the node library refuses to load.
pub fn trusted_setup_v1(
    include_prover_keys: bool,
) -> Result<circuit_keys::ParamsBlobV1, Box<dyn std::error::Error>> {
    use ark_bls12_381::Bls12_381;
    use ark_poly_commit::PolynomialCommitment;
    use rand::SeedableRng;

    type PC = plonk_core::commitment::KZG10<Bls12_381>;

    // Generate universal params large enough for the biggest circuit (Transfer at 2^15)
    // Deterministic seed for reproducible setup
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5646585F504C4E4B); // "VFX_PLNK" as u64
    let pp = PC::setup(
        circuit_keys::MAX_CIRCUIT_SIZE,
        None,
        &mut rng,
    ).map_err(|e| format!("KZG setup failed: {:?}", e))?;

    blob_from_params(&pp, include_prover_keys)
}

/// Compiles the circuits against `pp` and packs universal params + keys into the params blob (no magic: the caller's
/// `ParamsBlobV1::serialize_with_magic` says which setup produced it).
pub fn blob_from_params(
    pp: &<KZG10<ark_bls12_381::Bls12_381> as ark_poly_commit::PolynomialCommitment<ark_bls12_381::Fr, ark_poly::univariate::DensePolynomial<ark_bls12_381::Fr>>>::UniversalParams,
    include_prover_keys: bool,
) -> Result<circuit_keys::ParamsBlobV1, Box<dyn std::error::Error>> {
    use ark_serialize::CanonicalSerialize;
    let keys = circuit_keys::compile_all_circuits(pp, include_prover_keys)?;
    let mut pp_bytes = Vec::new();
    pp.serialize(&mut pp_bytes)?;
    fn ser<T: CanonicalSerialize>(t: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut b = Vec::new();
        t.serialize(&mut b)?;
        Ok(b)
    }
    fn ser_opt<T: CanonicalSerialize>(t: &Option<T>) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        Ok(match t { Some(v) => Some(ser(v)?), None => None })
    }
    Ok(circuit_keys::ParamsBlobV1 {
        universal_params: pp_bytes,
        shield_vk: ser(&keys.shield_vk)?,
        shield_pk: ser_opt(&keys.shield_pk)?,
        transfer_vk: ser(&keys.transfer_vk)?,
        transfer_pk: ser_opt(&keys.transfer_pk)?,
        unshield_vk: ser(&keys.unshield_vk)?,
        unshield_pk: ser_opt(&keys.unshield_pk)?,
        fee_vk: ser(&keys.fee_vk)?,
        fee_pk: ser_opt(&keys.fee_pk)?,
    })
}

/// Production params: the universal parameters come from the Zcash Sapling Powers of Tau (`phase1radix2m{k}` file,
/// k >= 16), whose secret is gone; the circuit keys are compiled against them. Written with magic `VXPLNK05`.
pub fn trusted_setup_from_zcash(
    phase1radix: &[u8],
    include_prover_keys: bool,
) -> Result<(circuit_keys::ParamsBlobV1, zcash_setup::ImportReport), Box<dyn std::error::Error>> {
    let (pp, report) = zcash_setup::universal_params_from_phase1radix(phase1radix, circuit_keys::MAX_CIRCUIT_SIZE)?;
    Ok((blob_from_params(&pp, include_prover_keys)?, report))
}
