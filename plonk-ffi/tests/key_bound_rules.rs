//! The key-bound rules through the C entry points: `plonk_prove_*3` make proofs that `plonk_verify3` accepts and
//! `plonk_verify2` / `plonk_verify` refuse, and proofs from `plonk_prove_*` keep verifying under `plonk_verify2` and
//! are refused by `plonk_verify3`. Needs the `VXPLNK06` params with prover keys (`VFX_PLONK_PARAMS`, or
//! `vfx_plonk_v4.params` in the workspace root); without them every test returns early and says so.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use plonk_core::proof_system::ProofRules;
use plonk_ffi::circuits_v1;
use plonk_ffi::poseidon_v1::{self, FixedDepthTree, TREE_DEPTH};
use plonk_ffi::vfxpi1::{encode_public_inputs_v3, Circuit, V2Fields};
use std::sync::Once;
use verifiedx_circuits::circuits::fee::FeeCircuit;

static LOAD: Once = Once::new();
static mut LOADED: bool = false;

fn params_loaded() -> bool {
    LOAD.call_once(|| {
        let path = std::env::var("VFX_PLONK_PARAMS").ok().or_else(|| {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("vfx_plonk_v4.params");
            p.exists().then(|| p.to_string_lossy().into_owned())
        });
        let Some(path) = path else {
            eprintln!("key_bound_rules: no params file (set VFX_PLONK_PARAMS); tests skipped");
            return;
        };
        let bytes = std::fs::read(&path).expect("read params");
        circuits_v1::try_load_v1_params(&bytes).expect("load VXPLNK06");
        unsafe { LOADED = circuits_v1::has_v1_prover_keys() };
    });
    unsafe { LOADED }
}

fn rand_fr(seed: u64) -> Fr {
    poseidon_v1::hash_2(Fr::from(seed), Fr::from(0xC0FFEEu64))
}

type Prove = unsafe extern "C" fn(u64, *const u8, *const u8, *mut u8, *mut usize, *mut u8, *mut usize) -> i32;
type Verify = extern "C" fn(u8, *const u8, usize, *const u8, usize) -> i32;

fn shield_with(prove: Prove, amount: u64, randomness: Fr, owner_pk: Fr) -> Vec<u8> {
    let (r, o) = (poseidon_v1::fr_to_le(&randomness), poseidon_v1::fr_to_le(&owner_pk));
    let (mut proof, mut pi) = (vec![0u8; 1 << 16], vec![0u8; 1 << 12]);
    let (mut proof_len, mut pi_len) = (proof.len(), pi.len());
    let code = unsafe { prove(amount, r.as_ptr(), o.as_ptr(), proof.as_mut_ptr(), &mut proof_len, pi.as_mut_ptr(), &mut pi_len) };
    assert_eq!(code, plonk_ffi::SUCCESS);
    proof.truncate(proof_len);
    proof
}

fn run(verify: Verify, circuit: Circuit, proof: &[u8], blob: &[u8]) -> i32 {
    verify(circuit as u8, proof.as_ptr(), proof.len(), blob.as_ptr(), blob.len())
}

#[test]
fn the_capability_bit_is_reported() {
    if !params_loaded() { return; }
    assert_ne!(plonk_ffi::plonk_capabilities() & plonk_ffi::PLONK_CAP_VERIFY3, 0);
    assert_eq!(plonk_ffi::PLONK_CAP_VERIFY3, 512);
}

#[test]
fn a_key_bound_shield_verifies_under_plonk_verify3_only() {
    if !params_loaded() { return; }
    let amount = 250_000_000u64;
    let (randomness, owner_pk) = (rand_fr(2), poseidon_v1::owner_pk(rand_fr(3)));
    let note_hash = [poseidon_v1::note_hash_v2(amount, randomness, owner_pk)];
    let fields = V2Fields { asset_tag: [7u8; 32], merkle_root: Fr::zero(), amount_or_fee: amount, transparent: 0, elements: &note_hash };
    let blob = encode_public_inputs_v3(Circuit::Shield, &fields).unwrap();
    let wrong = encode_public_inputs_v3(Circuit::Shield, &V2Fields { amount_or_fee: amount + 1, ..fields }).unwrap();

    let bound = shield_with(plonk_ffi::plonk_prove_shield3, amount, randomness, owner_pk);
    assert_eq!(run(plonk_ffi::plonk_verify3, Circuit::Shield, &bound, &blob), 1);
    assert_eq!(run(plonk_ffi::plonk_verify3, Circuit::Shield, &bound, &wrong), 0);
    assert_eq!(run(plonk_ffi::plonk_verify2, Circuit::Shield, &bound, &blob), 0);
    assert_eq!(run(plonk_ffi::plonk_verify, Circuit::Shield, &bound, &blob), 0);

    let current = shield_with(plonk_ffi::plonk_prove_shield, amount, randomness, owner_pk);
    assert_eq!(run(plonk_ffi::plonk_verify2, Circuit::Shield, &current, &blob), 1);
    assert_eq!(run(plonk_ffi::plonk_verify3, Circuit::Shield, &current, &blob), 0);
}

#[test]
fn a_key_bound_fee_verifies_under_the_key_bound_rules_only() {
    if !params_loaded() { return; }
    let nk = rand_fr(60);
    let dummy_hash = poseidon_v1::note_hash_v2(0, Fr::zero(), poseidon_v1::owner_pk(Fr::zero()));
    let mut tree = FixedDepthTree::new();
    tree.push(dummy_hash);
    let (amount, randomness, fee) = (5_000_000u64, rand_fr(61), 300u64);
    let note_hash = poseidon_v1::note_hash_v2(amount, randomness, poseidon_v1::owner_pk(nk));
    tree.push(note_hash);
    let root = tree.root();
    let change_randomness = rand_fr(62);
    let change_hash = poseidon_v1::note_hash_v2(amount - fee, change_randomness, poseidon_v1::owner_pk(nk));
    let path = tree.path(1).expect("path");
    let mut indices = [Fr::zero(); TREE_DEPTH];
    indices[0] = Fr::from(1u64);
    let circuit = || FeeCircuit {
        input_amount_scaled: Fr::from(amount),
        input_randomness: randomness,
        input_nullifier_key: nk,
        input_position: Fr::from(1u64),
        input_merkle_path: path,
        input_merkle_indices: indices,
        change_amount_scaled: Fr::from(amount - fee),
        change_randomness,
        change_owner_pk: poseidon_v1::owner_pk(nk),
        fee_scaled: Fr::from(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let elems = [poseidon_v1::nullifier(nk, note_hash, 1), change_hash];
    let blob = encode_public_inputs_v3(Circuit::Fee, &V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent: 0, elements: &elems }).unwrap();
    let verify = |proof: &[u8], rules| circuits_v1::ffi_verify_vfxpi3(Circuit::Fee as u8, proof, &blob, rules);

    let (bound, _) = circuits_v1::ffi_prove_fee_under(&mut circuit(), ProofRules::KeyBound).expect("prove fee, key-bound");
    assert_eq!(verify(&bound, ProofRules::KeyBound), Ok(true));
    assert_eq!(verify(&bound, ProofRules::Current), Ok(false));
    assert_eq!(run(plonk_ffi::plonk_verify3, Circuit::Fee, &bound, &blob), 1);
    assert_eq!(run(plonk_ffi::plonk_verify2, Circuit::Fee, &bound, &blob), 0);

    let (current, _) = circuits_v1::ffi_prove_fee(&mut circuit()).expect("prove fee");
    assert_eq!(verify(&current, ProofRules::Current), Ok(true));
    assert_eq!(verify(&current, ProofRules::KeyBound), Ok(false));

    // No prover makes proofs under the original rules.
    assert_eq!(circuits_v1::ffi_prove_fee_under(&mut circuit(), ProofRules::Legacy).err(), Some(plonk_ffi::ERR_NOT_IMPLEMENTED));
}
