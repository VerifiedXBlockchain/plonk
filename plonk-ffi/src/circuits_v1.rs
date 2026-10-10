//! FFI exports for the privacy circuits (Shield, Transfer, Unshield, Fee); v2 owner-bound circuits since the
//! Oct 2026 re-audit (params magic VXPLNK05 = v2 circuits over the Zcash Powers of Tau; public inputs VFXPI1 version 3).
//!
//! These functions use the real PLONK circuits from `verifiedx-circuits`
//! instead of the v0 digest-binding placeholder.

use std::sync::Mutex;

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use once_cell::sync::Lazy;
use plonk_core::commitment::KZG10;
use plonk_core::proof_system::pi::PublicInputs;
use plonk_core::proof_system::{ProverKey, VerifierKey};

use verifiedx_circuits::circuit_keys::{self, ParamsBlobV1, PARAMS_MAGIC_V1};
use verifiedx_circuits::circuits::fee::FeeCircuit;
use verifiedx_circuits::circuits::transfer::{TransferCircuit, TransferInput, TransferOutput};
use verifiedx_circuits::circuits::unshield::UnshieldCircuit;
use verifiedx_circuits::gadgets::merkle::TREE_DEPTH;

use crate::vfxpi1::{self, Circuit};

type PC = KZG10<Bls12_381>;
type UParams = <PC as ark_poly_commit::PolynomialCommitment<Fr, ark_poly::univariate::DensePolynomial<Fr>>>::UniversalParams;

/// Loaded v1 circuit keys (populated by `try_load_v1_params`).
pub(crate) static V1_STATE: Lazy<Mutex<Option<V1Loaded>>> =
    Lazy::new(|| Mutex::new(None));

pub(crate) struct V1Loaded {
    pub pp: UParams,
    pub shield_vk: VerifierKey<Fr, PC>,
    pub shield_pk: Option<ProverKey<Fr>>,
    pub transfer_vk: VerifierKey<Fr, PC>,
    pub transfer_pk: Option<ProverKey<Fr>>,
    pub unshield_vk: VerifierKey<Fr, PC>,
    pub unshield_pk: Option<ProverKey<Fr>>,
    pub fee_vk: VerifierKey<Fr, PC>,
    pub fee_pk: Option<ProverKey<Fr>>,
    /// Public-input gate positions per circuit, read from the circuit structure at load (witness-independent).
    pub shield_pi_pos: Vec<usize>,
    pub transfer_pi_pos: Vec<usize>,
    pub unshield_pi_pos: Vec<usize>,
    pub fee_pi_pos: Vec<usize>,
}

/// Try to load v1 params from the raw bytes. Returns Ok if successful.
pub fn try_load_v1_params(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < 8 || &bytes[..8] != PARAMS_MAGIC_V1 {
        if bytes.len() >= 8 && &bytes[..8] == circuit_keys::PARAMS_MAGIC_V1_CIRCUITS {
            return Err("VXPLNK03 carries the superseded v1 circuits (notes without an owner); this library needs VXPLNK05");
        }
        if bytes.len() >= 8 && &bytes[..8] == circuit_keys::PARAMS_MAGIC_SEEDED {
            return Err("VXPLNK04 was made with the seeded setup (public tau, forgeable proofs); this library needs VXPLNK05 (Zcash Powers of Tau)");
        }
        return Err("not VXPLNK05 format");
    }

    let blob = ParamsBlobV1::deserialize(bytes)?;

    let pp: UParams = CanonicalDeserialize::deserialize(blob.universal_params.as_slice())
        .map_err(|_| "failed to deserialize universal params")?;

    let shield_vk = CanonicalDeserialize::deserialize(blob.shield_vk.as_slice())
        .map_err(|_| "failed to deserialize shield vk")?;
    let shield_pk = blob.shield_pk.as_ref().map(|b| {
        CanonicalDeserialize::deserialize(b.as_slice()).expect("shield pk deserialize")
    });

    let transfer_vk = CanonicalDeserialize::deserialize(blob.transfer_vk.as_slice())
        .map_err(|_| "failed to deserialize transfer vk")?;
    let transfer_pk = blob.transfer_pk.as_ref().map(|b| {
        CanonicalDeserialize::deserialize(b.as_slice()).expect("transfer pk deserialize")
    });

    let unshield_vk = CanonicalDeserialize::deserialize(blob.unshield_vk.as_slice())
        .map_err(|_| "failed to deserialize unshield vk")?;
    let unshield_pk = blob.unshield_pk.as_ref().map(|b| {
        CanonicalDeserialize::deserialize(b.as_slice()).expect("unshield pk deserialize")
    });

    let fee_vk = CanonicalDeserialize::deserialize(blob.fee_vk.as_slice())
        .map_err(|_| "failed to deserialize fee vk")?;
    let fee_pk = blob.fee_pk.as_ref().map(|b| {
        CanonicalDeserialize::deserialize(b.as_slice()).expect("fee pk deserialize")
    });

    // Positions are a property of the circuits, not of the params: a few milliseconds each.
    let shield_pi_pos = circuit_keys::pi_positions_shield();
    let transfer_pi_pos = circuit_keys::pi_positions_transfer();
    let unshield_pi_pos = circuit_keys::pi_positions_unshield();
    let fee_pi_pos = circuit_keys::pi_positions_fee();

    *v1_lock() = Some(V1Loaded {
        pp,
        shield_vk,
        shield_pk,
        transfer_vk,
        transfer_pk,
        unshield_vk,
        unshield_pk,
        fee_vk,
        fee_pk,
        shield_pi_pos,
        transfer_pi_pos,
        unshield_pi_pos,
        fee_pi_pos,
    });

    Ok(())
}

/// The v1 state, recovering the lock if a panic ever poisoned it (one bad call must not disable the library).
fn v1_lock() -> std::sync::MutexGuard<'static, Option<V1Loaded>> {
    V1_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Check if v1 params are loaded.
pub fn is_v1_loaded() -> bool {
    v1_lock().is_some()
}

/// Check if v1 prover keys are available (for proving, not just verifying).
pub fn has_v1_prover_keys() -> bool {
    let guard = v1_lock();
    match guard.as_ref() {
        Some(state) => state.shield_pk.is_some(),
        None => false,
    }
}

/// The public-input positions of a circuit (empty when v1 is not loaded).
pub fn pi_positions(circuit: Circuit) -> Vec<usize> {
    let guard = v1_lock();
    match guard.as_ref() {
        None => Vec::new(),
        Some(s) => match circuit {
            Circuit::Shield => s.shield_pi_pos.clone(),
            Circuit::Transfer => s.transfer_pi_pos.clone(),
            Circuit::Unshield => s.unshield_pi_pos.clone(),
            Circuit::Fee => s.fee_pi_pos.clone(),
        },
    }
}

// ─── Shield FFI helpers ────────────────────────────────────────────

/// Prove a Shield circuit. Returns serialized (proof, pi) or error.
pub fn ffi_prove_shield(amount_scaled: u64, randomness_fr: Fr, owner_pk: Fr) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.shield_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::prove_shield(&state.pp, pk, Fr::from(amount_scaled), randomness_fr, owner_pk)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Shield circuit proof against the prover's own public-input encoding.
pub fn ffi_verify_shield(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::verify_shield(&state.pp, state.shield_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Transfer FFI helpers ──────────────────────────────────────────

/// Prove a Transfer circuit.
pub fn ffi_prove_transfer(circuit: &mut TransferCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.transfer_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::prove_transfer(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Transfer circuit proof against the prover's own public-input encoding.
pub fn ffi_verify_transfer(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::verify_transfer(&state.pp, state.transfer_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Unshield FFI helpers ──────────────────────────────────────────

/// Prove an Unshield circuit.
pub fn ffi_prove_unshield(circuit: &mut UnshieldCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.unshield_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::prove_unshield(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify an Unshield circuit proof against the prover's own public-input encoding.
pub fn ffi_verify_unshield(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::verify_unshield(&state.pp, state.unshield_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Fee FFI helpers ───────────────────────────────────────────────

/// Prove a Fee circuit.
pub fn ffi_prove_fee(circuit: &mut FeeCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.fee_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::prove_fee(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Fee circuit proof against the prover's own public-input encoding.
pub fn ffi_verify_fee(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    circuit_keys::verify_fee(&state.pp, state.fee_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Verify from the on-chain public inputs (VFXPI1 version 2) ─────

/// Verify a v2-circuit proof against a VFXPI1 **version 3** blob: the public inputs are rebuilt from the on-chain
/// fields at the circuit's own positions, so a validator never has to trust the prover's encoding.
/// `circuit_type` must equal the blob's circuit byte. Returns Ok(false) when the proof does not verify.
pub fn ffi_verify_vfxpi3(circuit_type: u8, proof_bytes: &[u8], pi_blob: &[u8]) -> Result<bool, i32> {
    let parsed = vfxpi1::parse_public_inputs_v3(pi_blob).map_err(|_| crate::ERR_PARAM)?;
    if parsed.circuit as u8 != circuit_type {
        return Err(crate::ERR_PARAM);
    }
    let guard = v1_lock();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let (positions, verify): (&Vec<usize>, fn(&UParams, VerifierKey<Fr, PC>, &[u8], &PublicInputs<Fr>) -> Result<bool, plonk_core::error::Error>) =
        match parsed.circuit {
            Circuit::Shield => (&state.shield_pi_pos, circuit_keys::verify_shield_pi),
            Circuit::Transfer => (&state.transfer_pi_pos, circuit_keys::verify_transfer_pi),
            Circuit::Unshield => (&state.unshield_pi_pos, circuit_keys::verify_unshield_pi),
            Circuit::Fee => (&state.fee_pi_pos, circuit_keys::verify_fee_pi),
        };
    let pi = circuit_keys::public_inputs_from_values(positions, &parsed.values).map_err(|_| crate::ERR_PARAM)?;
    let vk = match parsed.circuit {
        Circuit::Shield => state.shield_vk.clone(),
        Circuit::Transfer => state.transfer_vk.clone(),
        Circuit::Unshield => state.unshield_vk.clone(),
        Circuit::Fee => state.fee_vk.clone(),
    };
    verify(&state.pp, vk, proof_bytes, &pi).map_err(|_| crate::ERR_CRYPTO)
}

// ─── Witness deserialization helpers ───────────────────────────────

/// Deserialize a field element from 32 LE bytes.
pub(crate) fn fr_from_bytes(bytes: &[u8]) -> Result<Fr, i32> {
    use ark_serialize::CanonicalDeserialize;
    Fr::deserialize(bytes).map_err(|_| crate::ERR_CRYPTO)
}

/// Read a Merkle path (TREE_DEPTH field elements) from a flat byte buffer.
pub(crate) fn read_merkle_path(data: &[u8], offset: usize) -> Result<[Fr; TREE_DEPTH], i32> {
    let mut path = [Fr::from(0u64); TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        let start = offset + i * 32;
        if start + 32 > data.len() {
            return Err(crate::ERR_PARAM);
        }
        path[i] = fr_from_bytes(&data[start..start + 32])?;
    }
    Ok(path)
}

/// Size of one TransferInput in the flat wire format:
/// amount(8) + randomness(32) + nullifier_key(32) + position(8) + merkle_path(32*32) + merkle_indices(32*32)
pub const TRANSFER_INPUT_SIZE: usize = 8 + 32 + 32 + 8 + 32 * TREE_DEPTH + 32 * TREE_DEPTH;

/// Size of one TransferOutput in the flat wire format (v2): amount(8) + randomness(32) + owner_pk(32).
pub const TRANSFER_OUTPUT_SIZE: usize = 8 + 32 + 32;

/// Deserialize a TransferInput from the flat wire format.
pub(crate) fn read_transfer_input(data: &[u8]) -> Result<TransferInput<Fr>, i32> {
    if data.len() < TRANSFER_INPUT_SIZE {
        return Err(crate::ERR_PARAM);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let randomness = fr_from_bytes(&data[8..40])?;
    let nullifier_key = fr_from_bytes(&data[40..72])?;
    let position = u64::from_le_bytes(data[72..80].try_into().unwrap());
    let merkle_path = read_merkle_path(data, 80)?;
    let indices = read_merkle_path(data, 80 + 32 * TREE_DEPTH)?;
    Ok(TransferInput {
        amount_scaled: Fr::from(amount),
        randomness,
        nullifier_key,
        position: Fr::from(position),
        merkle_path,
        merkle_indices: indices,
    })
}

/// Deserialize a TransferOutput (amount + randomness + owner_pk).
pub(crate) fn read_transfer_output(data: &[u8]) -> Result<TransferOutput<Fr>, i32> {
    if data.len() < TRANSFER_OUTPUT_SIZE {
        return Err(crate::ERR_PARAM);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let randomness = fr_from_bytes(&data[8..40])?;
    let owner_pk = fr_from_bytes(&data[40..72])?;
    Ok(TransferOutput {
        amount_scaled: Fr::from(amount),
        randomness,
        owner_pk,
    })
}
