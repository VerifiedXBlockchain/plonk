//! FFI exports for v1 privacy circuits (Shield, Transfer, Unshield, Fee).
//!
//! These functions use the real PLONK circuits from `verifiedx-circuits`
//! instead of the v0 digest-binding placeholder.

use std::sync::Mutex;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use once_cell::sync::Lazy;
use plonk_core::commitment::KZG10;
use plonk_core::proof_system::{ProverKey, VerifierKey};

use verifiedx_circuits::circuit_keys::{self, CircuitKeys, ParamsBlobV1, PARAMS_MAGIC_V1};
use verifiedx_circuits::circuits::shield::ShieldCircuit;
use verifiedx_circuits::circuits::transfer::{TransferCircuit, TransferInput, TransferOutput};
use verifiedx_circuits::circuits::unshield::UnshieldCircuit;
use verifiedx_circuits::circuits::fee::FeeCircuit;
use verifiedx_circuits::gadgets::merkle::TREE_DEPTH;

type PC = KZG10<Bls12_381>;
type UParams = <PC as plonk_core::commitment::HomomorphicCommitment<Fr>>::UniversalParams;

/// Loaded v1 circuit keys (populated by `load_v1_params`).
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
}

/// Try to load v1 params from the raw bytes. Returns true if successful.
pub fn try_load_v1_params(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < 8 || &bytes[..8] != PARAMS_MAGIC_V1 {
        return Err("not VXPLNK03 format");
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

    *V1_STATE.lock().unwrap() = Some(V1Loaded {
        pp,
        shield_vk,
        shield_pk,
        transfer_vk,
        transfer_pk,
        unshield_vk,
        unshield_pk,
        fee_vk,
        fee_pk,
    });

    Ok(())
}

/// Check if v1 params are loaded.
pub fn is_v1_loaded() -> bool {
    V1_STATE.lock().unwrap().is_some()
}

/// Check if v1 prover keys are available (for proving, not just verifying).
pub fn has_v1_prover_keys() -> bool {
    let guard = V1_STATE.lock().unwrap();
    match guard.as_ref() {
        Some(state) => state.shield_pk.is_some(),
        None => false,
    }
}

// ─── Shield FFI helpers ────────────────────────────────────────────

/// Prove a Shield circuit. Returns serialized (proof, pi) or error.
pub fn ffi_prove_shield(amount_scaled: u64, randomness_fr: Fr) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.shield_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::prove_shield(&state.pp, pk, Fr::from(amount_scaled), randomness_fr)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Shield circuit proof.
pub fn ffi_verify_shield(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::verify_shield(&state.pp, state.shield_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Transfer FFI helpers ──────────────────────────────────────────

/// Prove a Transfer circuit.
pub fn ffi_prove_transfer(circuit: &mut TransferCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.transfer_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::prove_transfer(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Transfer circuit proof.
pub fn ffi_verify_transfer(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::verify_transfer(&state.pp, state.transfer_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Unshield FFI helpers ──────────────────────────────────────────

/// Prove an Unshield circuit.
pub fn ffi_prove_unshield(circuit: &mut UnshieldCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.unshield_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::prove_unshield(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify an Unshield circuit proof.
pub fn ffi_verify_unshield(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::verify_unshield(&state.pp, state.unshield_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
}

// ─── Fee FFI helpers ───────────────────────────────────────────────

/// Prove a Fee circuit.
pub fn ffi_prove_fee(circuit: &mut FeeCircuit<Fr>) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;
    let pk = state.fee_pk.clone().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::prove_fee(&state.pp, pk, circuit)
        .map_err(|_| crate::ERR_CRYPTO)
}

/// Verify a Fee circuit proof.
pub fn ffi_verify_fee(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<bool, i32> {
    let guard = V1_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(crate::ERR_NOT_IMPLEMENTED)?;

    circuit_keys::verify_fee(&state.pp, state.fee_vk.clone(), proof_bytes, pi_bytes)
        .map_err(|_| crate::ERR_CRYPTO)
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

/// Read a TransferInput from flat bytes: amount(8) + randomness(32) + viewing_key(32) + position(8) + path(32*32) + indices(32*32)
/// Total: 8 + 32 + 32 + 8 + 1024 + 1024 = 2128 bytes per input
pub const TRANSFER_INPUT_SIZE: usize = 8 + 32 + 32 + 8 + 32 * TREE_DEPTH + 32 * TREE_DEPTH;

pub(crate) fn read_transfer_input(data: &[u8]) -> Result<TransferInput<Fr>, i32> {
    if data.len() < TRANSFER_INPUT_SIZE {
        return Err(crate::ERR_PARAM);
    }
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let randomness = fr_from_bytes(&data[8..40])?;
    let viewing_key = fr_from_bytes(&data[40..72])?;
    let position = u64::from_le_bytes(data[72..80].try_into().unwrap());

    let path = read_merkle_path(data, 80)?;
    let indices = read_merkle_path(data, 80 + 32 * TREE_DEPTH)?;

    Ok(TransferInput {
        amount_scaled: Fr::from(amount),
        randomness,
        viewing_key,
        position: Fr::from(position),
        merkle_path: path,
        merkle_indices: indices,
    })
}
