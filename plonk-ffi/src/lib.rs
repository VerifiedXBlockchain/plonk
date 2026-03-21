//! C ABI for VerifiedX privacy primitives (Phase 1).
//! `plonk_verify` validates `PlonkPublicInputsV1` (VFXPI1), then — if `VXPLNK01` params were loaded — runs **v0** PLONK verify
//! (`verifiedx-circuits`: SHA-256 digest binding to the PI blob; not full Pedersen/Merkle/nullifier logic yet).

mod circuits_v1;
mod merkle;
mod pedersen;
mod poseidon_hash;
mod vfxpi1;

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use verifiedx_circuits::VfxPlonkParamsBlob;

static PARAMS: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));
/// `VXPLNK01` blob from `vfx_plonk_setup` / `verifiedx-circuits`; enables real `plonk_verify` (v0 digest binding).
static VFX_PLONK_V0: Lazy<Mutex<Option<VfxPlonkParamsBlob>>> =
    Lazy::new(|| Mutex::new(None));
static MERKLE: Lazy<Mutex<merkle::MerkleForest>> =
    Lazy::new(|| Mutex::new(merkle::MerkleForest::new()));

pub const SUCCESS: i32 = 0;
pub const ERR_NULL: i32 = -1;
pub const ERR_UTF8: i32 = -2;
pub const ERR_CRYPTO: i32 = -4;
pub const ERR_PARAM: i32 = -5;
pub const ERR_NOT_IMPLEMENTED: i32 = -6;

pub const G1_COMPRESSED_LEN: usize = 48;
pub const FR_LEN: usize = 32;

/// Bit 0: v0 PLONK verify available (`VXPLNK01` / `VXPLNK02` params loaded). Matches C# `PlonkNative.CapVerifyV1`.
pub const PLONK_CAP_VERIFY_V1: u32 = 1;
/// Bit 1: VFXPI1 layout parsing in `plonk_verify`.
pub const PLONK_CAP_PARSE_PUBLIC_INPUTS_V1: u32 = 2;
/// Bit 2: v0 proving available (`VXPLNK02` includes prover key). Matches C# `PlonkNative.CapProveV1`.
pub const PLONK_CAP_PROVE_V1: u32 = 4;
/// Bit 3: v1 real circuits loaded (`VXPLNK03` params).
pub const PLONK_CAP_V1_CIRCUITS: u32 = 8;
/// Bit 4: v1 prover keys available.
pub const PLONK_CAP_V1_PROVE: u32 = 16;

#[no_mangle]
pub extern "C" fn plonk_capabilities() -> u32 {
    let mut c = PLONK_CAP_PARSE_PUBLIC_INPUTS_V1;
    let guard = VFX_PLONK_V0.lock().unwrap();
    if let Some(ref blob) = *guard {
        c |= PLONK_CAP_VERIFY_V1;
        if blob.prover_key.is_some() {
            c |= PLONK_CAP_PROVE_V1;
        }
    }
    drop(guard);
    // v1 real circuit capabilities
    if circuits_v1::is_v1_loaded() {
        c |= PLONK_CAP_V1_CIRCUITS;
        if circuits_v1::has_v1_prover_keys() {
            c |= PLONK_CAP_V1_PROVE;
        }
    }
    c
}

#[no_mangle]
pub extern "C" fn plonk_load_params(params_path: *const c_char) -> i32 {
    if params_path.is_null() {
        return ERR_NULL;
    }
    let s = unsafe { CStr::from_ptr(params_path) };
    let path = match s.to_str() {
        Ok(p) => p,
        Err(_) => return ERR_UTF8,
    };
    match std::fs::read(path) {
        Ok(bytes) => {
            // Try v1 (VXPLNK03) first
            if bytes.len() >= 8 && &bytes[..8] == b"VXPLNK03" {
                match circuits_v1::try_load_v1_params(&bytes) {
                    Ok(()) => {
                        *PARAMS.lock().unwrap() = bytes;
                        return SUCCESS;
                    }
                    Err(_) => return ERR_CRYPTO,
                }
            }
            // Then try v0 (VXPLNK01 / VXPLNK02)
            let is_vfx_params = bytes.len() >= 8
                && (&bytes[..8] == b"VXPLNK01" || &bytes[..8] == b"VXPLNK02");
            if is_vfx_params {
                match VfxPlonkParamsBlob::deserialize(&bytes) {
                    Ok(blob) => {
                        *VFX_PLONK_V0.lock().unwrap() = Some(blob);
                        *PARAMS.lock().unwrap() = bytes;
                        SUCCESS
                    }
                    Err(_) => ERR_CRYPTO,
                }
            } else {
                *VFX_PLONK_V0.lock().unwrap() = None;
                let mut g = PARAMS.lock().unwrap();
                *g = bytes;
                SUCCESS
            }
        }
        Err(_) => ERR_CRYPTO,
    }
}

#[no_mangle]
pub extern "C" fn pedersen_commit(
    amount_scaled: u64,
    randomness: *const u8,
    commitment_out: *mut u8,
) -> i32 {
    if randomness.is_null() || commitment_out.is_null() {
        return ERR_NULL;
    }
    let r = unsafe { std::slice::from_raw_parts(randomness, 32) };
    match pedersen::commit(amount_scaled, r) {
        Ok(c) => {
            unsafe {
                std::ptr::copy_nonoverlapping(c.as_ptr(), commitment_out, G1_COMPRESSED_LEN);
            }
            SUCCESS
        }
        Err(_) => ERR_CRYPTO,
    }
}

#[no_mangle]
pub extern "C" fn pedersen_verify(
    commitment: *const u8,
    amount_scaled: u64,
    randomness: *const u8,
) -> i32 {
    if commitment.is_null() || randomness.is_null() {
        return ERR_NULL;
    }
    let c = unsafe { std::slice::from_raw_parts(commitment, G1_COMPRESSED_LEN) };
    let r = unsafe { std::slice::from_raw_parts(randomness, 32) };
    match pedersen::verify(c, amount_scaled, r) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn pedersen_commitment_add(
    commitment_a: *const u8,
    commitment_b: *const u8,
    commitment_out: *mut u8,
) -> i32 {
    if commitment_a.is_null() || commitment_b.is_null() || commitment_out.is_null() {
        return ERR_NULL;
    }
    let a = unsafe { std::slice::from_raw_parts(commitment_a, G1_COMPRESSED_LEN) };
    let b = unsafe { std::slice::from_raw_parts(commitment_b, G1_COMPRESSED_LEN) };
    match pedersen::commitment_add(a, b) {
        Ok(c) => {
            unsafe {
                std::ptr::copy_nonoverlapping(c.as_ptr(), commitment_out, G1_COMPRESSED_LEN);
            }
            SUCCESS
        }
        Err(_) => ERR_CRYPTO,
    }
}

#[no_mangle]
pub extern "C" fn poseidon_hash(
    inputs: *const u8,
    inputs_len: usize,
    hash_out: *mut u8,
) -> i32 {
    if inputs.is_null() || hash_out.is_null() {
        return ERR_NULL;
    }
    let data = unsafe { std::slice::from_raw_parts(inputs, inputs_len) };
    match poseidon_hash::hash_bytes(data) {
        Ok(h) => {
            unsafe {
                std::ptr::copy_nonoverlapping(h.as_ptr(), hash_out, FR_LEN);
            }
            SUCCESS
        }
        Err(_) => ERR_CRYPTO,
    }
}

#[no_mangle]
pub extern "C" fn merkle_tree_add(
    tree_id: *const c_char,
    commitment: *const u8,
    position_out: *mut u64,
) -> i32 {
    if tree_id.is_null() || commitment.is_null() || position_out.is_null() {
        return ERR_NULL;
    }
    let id = unsafe { CStr::from_ptr(tree_id) };
    let id = match id.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_UTF8,
    };
    let c = unsafe { std::slice::from_raw_parts(commitment, G1_COMPRESSED_LEN) };
    let mut g = MERKLE.lock().unwrap();
    let pos = g.add_leaf(&id, c);
    unsafe {
        *position_out = pos;
    }
    SUCCESS
}

#[no_mangle]
pub extern "C" fn merkle_tree_prove(
    tree_id: *const c_char,
    position: u64,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    root_out: *mut u8,
) -> i32 {
    if tree_id.is_null() || proof_out.is_null() || proof_out_len.is_null() || root_out.is_null() {
        return ERR_NULL;
    }
    let id = unsafe { CStr::from_ptr(tree_id) };
    let id = match id.to_str() {
        Ok(s) => s,
        Err(_) => return ERR_UTF8,
    };
    let g = MERKLE.lock().unwrap();
    let (proof, root) = match g.prove(id, position) {
        Some(p) => p,
        None => return ERR_PARAM,
    };
    let cap = unsafe { *proof_out_len };
    if cap < proof.len() {
        unsafe {
            *proof_out_len = proof.len();
        }
        return ERR_PARAM;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len());
        *proof_out_len = proof.len();
        std::ptr::copy_nonoverlapping(root.as_ptr(), root_out, FR_LEN);
    }
    SUCCESS
}

#[no_mangle]
pub extern "C" fn nullifier_derive(
    viewing_key: *const u8,
    commitment: *const u8,
    tree_position: u64,
    nullifier_out: *mut u8,
) -> i32 {
    if viewing_key.is_null() || commitment.is_null() || nullifier_out.is_null() {
        return ERR_NULL;
    }
    let vk = unsafe { std::slice::from_raw_parts(viewing_key, 32) };
    let c = unsafe { std::slice::from_raw_parts(commitment, G1_COMPRESSED_LEN) };
    match poseidon_hash::nullifier_from_parts(vk, c, tree_position) {
        Ok(n) => {
            unsafe {
                std::ptr::copy_nonoverlapping(n.as_ptr(), nullifier_out, FR_LEN);
            }
            SUCCESS
        }
        Err(_) => ERR_CRYPTO,
    }
}

/// Derive a nullifier using note_hash (v1 circuit-compatible).
///
/// `nullifier = Poseidon(viewing_key, note_hash, position)`
///
/// This matches the in-circuit nullifier derivation used by the v1 circuits.
/// The `note_hash` parameter should be the output of `poseidon_note_hash()`.
///
/// # Safety
/// `viewing_key` and `note_hash` must point to 32 bytes each.
/// `nullifier_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nullifier_derive_v1(
    viewing_key: *const u8,
    note_hash: *const u8,
    tree_position: u64,
    nullifier_out: *mut u8,
) -> i32 {
    if viewing_key.is_null() || note_hash.is_null() || nullifier_out.is_null() {
        return ERR_NULL;
    }
    let vk = std::slice::from_raw_parts(viewing_key, FR_LEN);
    let nh = std::slice::from_raw_parts(note_hash, FR_LEN);
    match poseidon_hash::nullifier_from_note_hash(vk, nh, tree_position) {
        Ok(n) => {
            std::ptr::copy_nonoverlapping(n.as_ptr(), nullifier_out, FR_LEN);
            SUCCESS
        }
        Err(_) => ERR_CRYPTO,
    }
}

#[no_mangle]
pub extern "C" fn plonk_verify(
    circuit_type: u8,
    proof: *const u8,
    proof_len: usize,
    public_inputs: *const u8,
    public_inputs_len: usize,
) -> i32 {
    if proof.is_null() || public_inputs.is_null() {
        return ERR_NULL;
    }
    // Preserve legacy "stub" behavior for empty buffers (C# tests / no-op callers).
    if proof_len == 0 || public_inputs_len == 0 {
        return ERR_NOT_IMPLEMENTED;
    }
    let pi_slice = unsafe { std::slice::from_raw_parts(public_inputs, public_inputs_len) };
    let proof_slice = unsafe { std::slice::from_raw_parts(proof, proof_len) };

    // Try v1 real circuits first (if loaded)
    if circuits_v1::is_v1_loaded() {
        let result = match circuit_type {
            1 => circuits_v1::ffi_verify_shield(proof_slice, pi_slice),
            0 => circuits_v1::ffi_verify_transfer(proof_slice, pi_slice),
            2 => circuits_v1::ffi_verify_unshield(proof_slice, pi_slice),
            3 => circuits_v1::ffi_verify_fee(proof_slice, pi_slice),
            _ => return ERR_PARAM,
        };
        return match result {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => e,
        };
    }

    // Fall back to v0 digest-binding circuit
    let parsed = match vfxpi1::parse_public_inputs(pi_slice) {
        Ok(c) => c,
        Err(()) => return ERR_PARAM,
    };
    if circuit_type != parsed as u8 {
        return 0;
    }
    if let Some(ref blob) = *VFX_PLONK_V0.lock().unwrap() {
        return match verifiedx_circuits::verify_vfxpi_v0(blob, proof_slice, pi_slice) {
            Ok(()) => 1,
            Err(_) => 0,
        };
    }
    ERR_NOT_IMPLEMENTED
}

/// Generate a v0 PLONK proof for `public_inputs` (full VFXPI1 blob). Requires **`VXPLNK02`** params with prover key.
/// `proof_out_len` is input capacity / output written length. If buffer is too small, returns `ERR_PARAM` and sets
/// `*proof_out_len` to the required byte length.
#[no_mangle]
pub extern "C" fn plonk_prove_v0(
    circuit_type: u8,
    public_inputs: *const u8,
    public_inputs_len: usize,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
) -> i32 {
    if public_inputs.is_null() || proof_out_len.is_null() {
        return ERR_NULL;
    }
    let pi = unsafe { std::slice::from_raw_parts(public_inputs, public_inputs_len) };
    let parsed = match vfxpi1::parse_public_inputs(pi) {
        Ok(c) => c,
        Err(()) => return ERR_PARAM,
    };
    if circuit_type != parsed as u8 {
        return ERR_PARAM;
    }
    let guard = VFX_PLONK_V0.lock().unwrap();
    let blob = match guard.as_ref() {
        Some(b) if b.prover_key.is_some() => b,
        Some(_) => return ERR_NOT_IMPLEMENTED,
        None => return ERR_NOT_IMPLEMENTED,
    };
    let proof_vec = match verifiedx_circuits::prove_vfxpi_v0(blob, pi) {
        Ok(p) => p,
        Err(_) => return ERR_CRYPTO,
    };
    if proof_out.is_null() {
        unsafe {
            *proof_out_len = proof_vec.len();
        }
        return ERR_PARAM;
    }
    let cap = unsafe { *proof_out_len };
    if cap < proof_vec.len() {
        unsafe {
            *proof_out_len = proof_vec.len();
        }
        return ERR_PARAM;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(proof_vec.as_ptr(), proof_out, proof_vec.len());
        *proof_out_len = proof_vec.len();
    }
    SUCCESS
}

/// Generate a Shield circuit proof (v1). Requires `VXPLNK03` params with prover keys.
///
/// # Safety
/// `randomness` must point to 32 bytes. `proof_out` must point to `*proof_out_len` writable bytes.
/// `pi_out` must point to `*pi_out_len` writable bytes.
/// On success, `*proof_out_len` and `*pi_out_len` are set to the actual written lengths.
/// If buffers are too small, returns `ERR_PARAM` and sets the required lengths.
#[no_mangle]
pub unsafe extern "C" fn plonk_prove_shield(
    amount_scaled: u64,
    randomness: *const u8,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    pi_out: *mut u8,
    pi_out_len: *mut usize,
) -> i32 {
    if randomness.is_null() || proof_out_len.is_null() || pi_out_len.is_null() {
        return ERR_NULL;
    }

    let rand_slice = std::slice::from_raw_parts(randomness, 32);
    let randomness_fr = match ark_serialize::CanonicalDeserialize::deserialize(rand_slice) {
        Ok(f) => f,
        Err(_) => return ERR_CRYPTO,
    };

    let (proof_bytes, pi_bytes) = match circuits_v1::ffi_prove_shield(amount_scaled, randomness_fr) {
        Ok(r) => r,
        Err(e) => return e,
    };

    write_proof_and_pi(proof_out, proof_out_len, pi_out, pi_out_len, &proof_bytes, &pi_bytes)
}

/// Generate a Transfer circuit proof (v1, 2-in/2-out).
///
/// # Wire format for `witness_data`:
/// For each of 2 inputs (sequentially):
///   - amount_scaled: u64 LE (8 bytes)
///   - randomness: Fr LE (32 bytes)
///   - viewing_key: Fr LE (32 bytes)
///   - position: u64 LE (8 bytes)
///   - merkle_path: 32 × Fr LE (32×32 = 1024 bytes)
///   - merkle_indices: 32 × Fr LE (1024 bytes)
/// Then 2 outputs:
///   - amount_scaled: u64 LE (8 bytes)
///   - randomness: Fr LE (32 bytes)
/// Then:
///   - fee_scaled: u64 LE (8 bytes)
///   - merkle_root: Fr LE (32 bytes)
///
/// Total = 2×2128 + 2×40 + 8 + 32 = 4384 bytes
#[no_mangle]
pub unsafe extern "C" fn plonk_prove_transfer(
    witness_data: *const u8,
    witness_data_len: usize,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    pi_out: *mut u8,
    pi_out_len: *mut usize,
) -> i32 {
    if witness_data.is_null() || proof_out_len.is_null() || pi_out_len.is_null() {
        return ERR_NULL;
    }

    let data = std::slice::from_raw_parts(witness_data, witness_data_len);

    let expected_len = 2 * circuits_v1::TRANSFER_INPUT_SIZE + 2 * 40 + 8 + 32;
    if data.len() < expected_len {
        return ERR_PARAM;
    }

    use verifiedx_circuits::circuits::transfer::{TransferCircuit, TransferInput, TransferOutput};
    use ark_bls12_381::Fr;

    // Read 2 inputs
    let input0 = match circuits_v1::read_transfer_input(&data[0..circuits_v1::TRANSFER_INPUT_SIZE]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let input1 = match circuits_v1::read_transfer_input(&data[circuits_v1::TRANSFER_INPUT_SIZE..2*circuits_v1::TRANSFER_INPUT_SIZE]) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let mut cursor = 2 * circuits_v1::TRANSFER_INPUT_SIZE;

    // Read 2 outputs (amount u64 LE + randomness Fr)
    let out0_amount = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    let out0_rand = match circuits_v1::fr_from_bytes(&data[cursor+8..cursor+40]) {
        Ok(f) => f,
        Err(e) => return e,
    };
    cursor += 40;
    let out1_amount = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    let out1_rand = match circuits_v1::fr_from_bytes(&data[cursor+8..cursor+40]) {
        Ok(f) => f,
        Err(e) => return e,
    };
    cursor += 40;

    let fee = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let merkle_root = match circuits_v1::fr_from_bytes(&data[cursor..cursor+32]) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let mut circuit = TransferCircuit {
        inputs: [input0, input1],
        outputs: [
            TransferOutput { amount_scaled: Fr::from(out0_amount), randomness: out0_rand },
            TransferOutput { amount_scaled: Fr::from(out1_amount), randomness: out1_rand },
        ],
        fee_scaled: Fr::from(fee),
        merkle_root,
        pi_pos: Vec::new(),
    };

    let (proof_bytes, pi_bytes) = match circuits_v1::ffi_prove_transfer(&mut circuit) {
        Ok(r) => r,
        Err(e) => return e,
    };

    write_proof_and_pi(proof_out, proof_out_len, pi_out, pi_out_len, &proof_bytes, &pi_bytes)
}

/// Generate an Unshield circuit proof (v1).
///
/// # Wire format for `witness_data`:
/// 2 inputs (same format as Transfer input, 2×2128 bytes)
/// Then:
///   - transparent_amount_scaled: u64 LE (8 bytes)
///   - change_amount_scaled: u64 LE (8 bytes)
///   - change_randomness: Fr LE (32 bytes)
///   - fee_scaled: u64 LE (8 bytes)
///   - merkle_root: Fr LE (32 bytes)
///
/// Total = 2×2128 + 88 = 4344 bytes
#[no_mangle]
pub unsafe extern "C" fn plonk_prove_unshield(
    witness_data: *const u8,
    witness_data_len: usize,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    pi_out: *mut u8,
    pi_out_len: *mut usize,
) -> i32 {
    if witness_data.is_null() || proof_out_len.is_null() || pi_out_len.is_null() {
        return ERR_NULL;
    }

    let data = std::slice::from_raw_parts(witness_data, witness_data_len);

    let expected_len = 2 * circuits_v1::TRANSFER_INPUT_SIZE + 88;
    if data.len() < expected_len {
        return ERR_PARAM;
    }

    use verifiedx_circuits::circuits::unshield::UnshieldCircuit;
    use ark_bls12_381::Fr;

    let input0 = match circuits_v1::read_transfer_input(&data[0..circuits_v1::TRANSFER_INPUT_SIZE]) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let input1 = match circuits_v1::read_transfer_input(&data[circuits_v1::TRANSFER_INPUT_SIZE..2*circuits_v1::TRANSFER_INPUT_SIZE]) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let mut cursor = 2 * circuits_v1::TRANSFER_INPUT_SIZE;

    let transparent_amount = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let change_amount = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let change_rand = match circuits_v1::fr_from_bytes(&data[cursor..cursor+32]) {
        Ok(f) => f,
        Err(e) => return e,
    };
    cursor += 32;
    let fee = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let merkle_root = match circuits_v1::fr_from_bytes(&data[cursor..cursor+32]) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let mut circuit = UnshieldCircuit {
        inputs: [input0, input1],
        transparent_amount_scaled: Fr::from(transparent_amount),
        change_amount_scaled: Fr::from(change_amount),
        change_randomness: change_rand,
        fee_scaled: Fr::from(fee),
        merkle_root,
        pi_pos: Vec::new(),
    };

    let (proof_bytes, pi_bytes) = match circuits_v1::ffi_prove_unshield(&mut circuit) {
        Ok(r) => r,
        Err(e) => return e,
    };

    write_proof_and_pi(proof_out, proof_out_len, pi_out, pi_out_len, &proof_bytes, &pi_bytes)
}

/// Generate a Fee circuit proof (v1, 1-in/1-out).
///
/// # Wire format for `witness_data`:
/// 1 input (same format as Transfer input, 2128 bytes)
/// Then:
///   - change_amount_scaled: u64 LE (8 bytes)
///   - change_randomness: Fr LE (32 bytes)
///   - fee_scaled: u64 LE (8 bytes)
///   - merkle_root: Fr LE (32 bytes)
///
/// Total = 2128 + 80 = 2208 bytes
#[no_mangle]
pub unsafe extern "C" fn plonk_prove_fee(
    witness_data: *const u8,
    witness_data_len: usize,
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    pi_out: *mut u8,
    pi_out_len: *mut usize,
) -> i32 {
    if witness_data.is_null() || proof_out_len.is_null() || pi_out_len.is_null() {
        return ERR_NULL;
    }

    let data = std::slice::from_raw_parts(witness_data, witness_data_len);

    let expected_len = circuits_v1::TRANSFER_INPUT_SIZE + 80;
    if data.len() < expected_len {
        return ERR_PARAM;
    }

    use verifiedx_circuits::circuits::fee::FeeCircuit;
    use verifiedx_circuits::gadgets::merkle::TREE_DEPTH;
    use ark_bls12_381::Fr;

    // Read input (reuse transfer_input reader since format is the same)
    let input = match circuits_v1::read_transfer_input(&data[0..circuits_v1::TRANSFER_INPUT_SIZE]) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let mut cursor = circuits_v1::TRANSFER_INPUT_SIZE;

    let change_amount = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let change_rand = match circuits_v1::fr_from_bytes(&data[cursor..cursor+32]) {
        Ok(f) => f,
        Err(e) => return e,
    };
    cursor += 32;
    let fee = u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap());
    cursor += 8;
    let merkle_root = match circuits_v1::fr_from_bytes(&data[cursor..cursor+32]) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let mut circuit = FeeCircuit {
        input_amount_scaled: input.amount_scaled,
        input_randomness: input.randomness,
        input_viewing_key: input.viewing_key,
        input_position: input.position,
        input_merkle_path: input.merkle_path,
        input_merkle_indices: input.merkle_indices,
        change_amount_scaled: Fr::from(change_amount),
        change_randomness: change_rand,
        fee_scaled: Fr::from(fee),
        merkle_root,
        pi_pos: Vec::new(),
    };

    let (proof_bytes, pi_bytes) = match circuits_v1::ffi_prove_fee(&mut circuit) {
        Ok(r) => r,
        Err(e) => return e,
    };

    write_proof_and_pi(proof_out, proof_out_len, pi_out, pi_out_len, &proof_bytes, &pi_bytes)
}

/// Helper: write proof + pi bytes to output buffers with length checking.
unsafe fn write_proof_and_pi(
    proof_out: *mut u8,
    proof_out_len: *mut usize,
    pi_out: *mut u8,
    pi_out_len: *mut usize,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> i32 {
    if proof_out.is_null() || *proof_out_len < proof_bytes.len() {
        *proof_out_len = proof_bytes.len();
        if !pi_out.is_null() {
            *pi_out_len = pi_bytes.len();
        }
        return ERR_PARAM;
    }
    std::ptr::copy_nonoverlapping(proof_bytes.as_ptr(), proof_out, proof_bytes.len());
    *proof_out_len = proof_bytes.len();

    if pi_out.is_null() || *pi_out_len < pi_bytes.len() {
        *pi_out_len = pi_bytes.len();
        return ERR_PARAM;
    }
    std::ptr::copy_nonoverlapping(pi_bytes.as_ptr(), pi_out, pi_bytes.len());
    *pi_out_len = pi_bytes.len();

    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pedersen_roundtrip() {
        let r = [7u8; 32];
        let mut c = [0u8; G1_COMPRESSED_LEN];
        assert_eq!(pedersen_commit(12345, r.as_ptr(), c.as_mut_ptr()), SUCCESS);
        assert_eq!(pedersen_verify(c.as_ptr(), 12345, r.as_ptr()), 1);
    }
}
