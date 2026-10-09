//! End-to-end tests of the v1 circuits against the on-chain public-input encoding (VFXPI1 version 2) and the
//! circuit-compatible native Poseidon. They need the production `VXPLNK03` params with prover keys: set
//! `VFX_PLONK_PARAMS` to the file, or place `vfx_plonk_v1.params` in the workspace root. Without it every test
//! here returns early (and says so), so `cargo test` stays green on machines without the 240 MB file.
//!
//! What they pin down for the Core node and wallet:
//!  - `poseidon_note_hash` / `poseidon_hash_2` / `poseidon_hash_3` equal the circuits' in-circuit values;
//!  - a fixed-depth-32 tree with `poseidon_merkle_zero` padding is the tree the circuits accept;
//!  - a proof verifies against a VFXPI1 v2 blob built from on-chain fields, and not against a tampered one;
//!  - a one-note spend uses a dummy zero note (amount 0, randomness 0) as its second input.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use plonk_ffi::circuits_v1;
use plonk_ffi::poseidon_v1::{self, FixedDepthTree, TREE_DEPTH};
use plonk_ffi::vfxpi1::{self, encode_public_inputs_v2, Circuit, V2Fields};
use std::sync::Once;
use verifiedx_circuits::circuit_keys;
use verifiedx_circuits::circuits::fee::FeeCircuit;
use verifiedx_circuits::circuits::transfer::{TransferCircuit, TransferInput, TransferOutput};
use verifiedx_circuits::circuits::unshield::UnshieldCircuit;

static LOAD: Once = Once::new();
static mut LOADED: bool = false;

fn params_loaded() -> bool {
    LOAD.call_once(|| {
        let path = std::env::var("VFX_PLONK_PARAMS").ok().or_else(|| {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("vfx_plonk_v1.params");
            p.exists().then(|| p.to_string_lossy().into_owned())
        });
        let Some(path) = path else {
            eprintln!("v1_vfxpi2: no params file (set VFX_PLONK_PARAMS); tests skipped");
            return;
        };
        let bytes = std::fs::read(&path).expect("read params");
        circuits_v1::try_load_v1_params(&bytes).expect("load VXPLNK03");
        unsafe { LOADED = circuits_v1::has_v1_prover_keys() };
        if !unsafe { LOADED } {
            eprintln!("v1_vfxpi2: params carry no prover keys; tests skipped");
        }
    });
    unsafe { LOADED }
}

fn fr(n: u64) -> Fr {
    Fr::from(n)
}

fn verify(circuit: Circuit, proof: &[u8], pi_blob: &[u8]) -> Result<bool, i32> {
    circuits_v1::ffi_verify_vfxpi2(circuit as u8, proof, pi_blob)
}

/// Field-element little-endian bytes made from a seed (always canonical).
fn rand_fr(seed: u64) -> Fr {
    poseidon_v1::hash_2(fr(seed), fr(0xC0FFEE))
}

fn transfer_input(tree: &FixedDepthTree, position: u64, amount: u64, randomness: Fr, viewing_key: Fr) -> TransferInput<Fr> {
    let path = tree.path(position).expect("path");
    let mut indices = [Fr::zero(); TREE_DEPTH];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = fr((position >> i) & 1);
    }
    TransferInput { amount_scaled: fr(amount), randomness, viewing_key, position: fr(position), merkle_path: path, merkle_indices: indices }
}

// ─── Poseidon equality with the circuits ──────────────────────────────────────────────────────────────

#[test]
fn native_note_hash_equals_the_circuits() {
    if !params_loaded() { return; }
    let amount = 100_000_000u64;
    let randomness = rand_fr(1);
    let (proof, pi_bytes) = circuits_v1::ffi_prove_shield(amount, randomness).expect("prove shield");
    // The prover's own encoding lists the circuit's public inputs, negated: [-amount, -note_hash].
    let pi = circuit_keys::deserialize_public_inputs(&pi_bytes).expect("pi");
    let vals: Vec<Fr> = pi.get_vals().copied().collect();
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], -fr(amount));
    assert_eq!(vals[1], -poseidon_v1::note_hash(amount, randomness), "native Poseidon is not the circuits' Poseidon");
    // Positions read from the circuit structure are the positions the prover used.
    let pos: Vec<usize> = pi.get_pos().copied().collect();
    assert_eq!(pos, circuits_v1::pi_positions(Circuit::Shield));
    assert!(circuits_v1::ffi_verify_shield(&proof, &pi_bytes).unwrap());
}

// ─── Shield ───────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn shield_verifies_against_vfxpi2_and_refuses_tampering() {
    if !params_loaded() { return; }
    let amount = 250_000_000u64;
    let randomness = rand_fr(2);
    let (proof, _) = circuits_v1::ffi_prove_shield(amount, randomness).unwrap();
    let note_hash = poseidon_v1::note_hash(amount, randomness);
    let fields = V2Fields { asset_tag: [7u8; 32], merkle_root: Fr::zero(), amount_or_fee: amount, transparent: 0, elements: &[note_hash] };
    let blob = encode_public_inputs_v2(Circuit::Shield, &fields).unwrap();
    assert_eq!(verify(Circuit::Shield, &proof, &blob), Ok(true));

    // Another amount, another note hash, the wrong circuit byte: all refused.
    let other_amount = V2Fields { amount_or_fee: amount + 1, ..fields };
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v2(Circuit::Shield, &other_amount).unwrap()), Ok(false));
    let other_hash = [poseidon_v1::note_hash(amount, rand_fr(3))];
    let other = V2Fields { elements: &other_hash, ..fields };
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v2(Circuit::Shield, &other).unwrap()), Ok(false));
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Err(plonk_ffi::ERR_PARAM));
    // The asset tag is not a circuit input: the same proof verifies under any tag (it is bound by the tx hash).
    let other_tag = V2Fields { asset_tag: [1u8; 32], ..fields };
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v2(Circuit::Shield, &other_tag).unwrap()), Ok(true));
}

// ─── Unshield with the fixed-depth tree ───────────────────────────────────────────────────────────────

#[test]
fn unshield_two_notes_verifies_against_vfxpi2_built_from_the_tree() {
    if !params_loaded() { return; }
    let vk = rand_fr(10);
    let notes = [(300_000_000u64, rand_fr(11)), (200_000_000u64, rand_fr(12)), (50_000_000u64, rand_fr(13))];
    let mut tree = FixedDepthTree::new();
    for (a, r) in &notes {
        tree.push(poseidon_v1::note_hash(*a, *r));
    }
    let root = tree.root();
    let fee = 300u64;
    let transparent = 400_000_000u64;
    let change = notes[0].0 + notes[1].0 - transparent - fee;
    let change_rand = rand_fr(14);

    let mut circuit = UnshieldCircuit {
        inputs: [transfer_input(&tree, 0, notes[0].0, notes[0].1, vk), transfer_input(&tree, 1, notes[1].0, notes[1].1, vk)],
        transparent_amount_scaled: fr(transparent),
        change_amount_scaled: fr(change),
        change_randomness: change_rand,
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, pi_bytes) = circuits_v1::ffi_prove_unshield(&mut circuit).expect("prove unshield");
    assert!(circuits_v1::ffi_verify_unshield(&proof, &pi_bytes).unwrap(), "prover's own public inputs");

    let null0 = poseidon_v1::nullifier(vk, poseidon_v1::note_hash(notes[0].0, notes[0].1), 0);
    let null1 = poseidon_v1::nullifier(vk, poseidon_v1::note_hash(notes[1].0, notes[1].1), 1);
    let change_hash = poseidon_v1::note_hash(change, change_rand);
    let elems = [null0, null1, change_hash];
    let fields = V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent, elements: &elems };
    let blob = encode_public_inputs_v2(Circuit::Unshield, &fields).unwrap();
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Ok(true), "VFXPI1 v2 built from native tree, nullifiers and change hash");

    // The prover's encoding and the rebuilt one carry the same values at the same positions.
    let pi = circuit_keys::deserialize_public_inputs(&pi_bytes).unwrap();
    let rebuilt = circuit_keys::public_inputs_from_values(&circuits_v1::pi_positions(Circuit::Unshield), &vfxpi1::parse_public_inputs_v2(&blob).unwrap().values).unwrap();
    assert_eq!(pi, rebuilt);

    // A different transparent amount or a wrong root is refused.
    let more = V2Fields { transparent: transparent + 1, ..fields };
    assert_eq!(verify(Circuit::Unshield, &proof, &encode_public_inputs_v2(Circuit::Unshield, &more).unwrap()), Ok(false));
    let other_root = V2Fields { merkle_root: fr(1), ..fields };
    assert_eq!(verify(Circuit::Unshield, &proof, &encode_public_inputs_v2(Circuit::Unshield, &other_root).unwrap()), Ok(false));
}

#[test]
fn unshield_one_note_uses_a_dummy_zero_note() {
    if !params_loaded() { return; }
    // Convention for the node: leaf 0 of every tree is the public dummy note (amount 0, randomness 0). Its nullifier
    // differs per spender (it includes the viewing key), so each spender "spends" it once; it adds nothing.
    let vk = rand_fr(20);
    let mut tree = FixedDepthTree::new();
    tree.push(poseidon_v1::note_hash(0, Fr::zero())); // position 0: the dummy
    let (amount, rnd) = (120_000_000u64, rand_fr(21));
    tree.push(poseidon_v1::note_hash(amount, rnd)); // position 1: the real note
    let root = tree.root();
    let fee = 300u64;
    let transparent = 100_000_000u64;
    let change = amount - transparent - fee;
    let change_rand = rand_fr(22);
    let mut circuit = UnshieldCircuit {
        inputs: [transfer_input(&tree, 1, amount, rnd, vk), transfer_input(&tree, 0, 0, Fr::zero(), vk)],
        transparent_amount_scaled: fr(transparent),
        change_amount_scaled: fr(change),
        change_randomness: change_rand,
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, _) = circuits_v1::ffi_prove_unshield(&mut circuit).expect("prove");
    let elems = [
        poseidon_v1::nullifier(vk, poseidon_v1::note_hash(amount, rnd), 1),
        poseidon_v1::nullifier(vk, poseidon_v1::note_hash(0, Fr::zero()), 0),
        poseidon_v1::note_hash(change, change_rand),
    ];
    let blob = encode_public_inputs_v2(Circuit::Unshield, &V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent, elements: &elems }).unwrap();
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Ok(true));
}

// ─── Transfer ─────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn transfer_verifies_against_vfxpi2() {
    if !params_loaded() { return; }
    let vk = rand_fr(30);
    let ins = [(500_000_000u64, rand_fr(31)), (100_000_000u64, rand_fr(32))];
    let mut tree = FixedDepthTree::new();
    tree.push(poseidon_v1::note_hash(0, Fr::zero()));
    for (a, r) in &ins {
        tree.push(poseidon_v1::note_hash(*a, *r));
    }
    let root = tree.root();
    let fee = 300u64;
    let outs = [(350_000_000u64, rand_fr(33)), (ins[0].0 + ins[1].0 - 350_000_000 - fee, rand_fr(34))];
    let mut circuit = TransferCircuit {
        inputs: [transfer_input(&tree, 1, ins[0].0, ins[0].1, vk), transfer_input(&tree, 2, ins[1].0, ins[1].1, vk)],
        outputs: [TransferOutput { amount_scaled: fr(outs[0].0), randomness: outs[0].1 }, TransferOutput { amount_scaled: fr(outs[1].0), randomness: outs[1].1 }],
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, pi_bytes) = circuits_v1::ffi_prove_transfer(&mut circuit).expect("prove transfer");
    assert!(circuits_v1::ffi_verify_transfer(&proof, &pi_bytes).unwrap());
    let elems = [
        poseidon_v1::nullifier(vk, poseidon_v1::note_hash(ins[0].0, ins[0].1), 1),
        poseidon_v1::nullifier(vk, poseidon_v1::note_hash(ins[1].0, ins[1].1), 2),
        poseidon_v1::note_hash(outs[0].0, outs[0].1),
        poseidon_v1::note_hash(outs[1].0, outs[1].1),
    ];
    let fields = V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent: 0, elements: &elems };
    assert_eq!(verify(Circuit::Transfer, &proof, &encode_public_inputs_v2(Circuit::Transfer, &fields).unwrap()), Ok(true));
    let swapped = [elems[1], elems[0], elems[2], elems[3]];
    assert_eq!(verify(Circuit::Transfer, &proof, &encode_public_inputs_v2(Circuit::Transfer, &V2Fields { elements: &swapped, ..fields }).unwrap()), Ok(false));
}

// ─── Fee ──────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn fee_verifies_against_vfxpi2() {
    if !params_loaded() { return; }
    let vk = rand_fr(40);
    let (amount, rnd) = (5_000_000u64, rand_fr(41));
    let mut tree = FixedDepthTree::new();
    tree.push(poseidon_v1::note_hash(0, Fr::zero()));
    tree.push(poseidon_v1::note_hash(amount, rnd));
    let root = tree.root();
    let fee = 300u64;
    let change = amount - fee;
    let change_rand = rand_fr(42);
    let input = transfer_input(&tree, 1, amount, rnd, vk);
    let mut circuit = FeeCircuit {
        input_amount_scaled: fr(amount),
        input_randomness: rnd,
        input_viewing_key: vk,
        input_position: fr(1),
        input_merkle_path: input.merkle_path,
        input_merkle_indices: input.merkle_indices,
        change_amount_scaled: fr(change),
        change_randomness: change_rand,
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, pi_bytes) = circuits_v1::ffi_prove_fee(&mut circuit).expect("prove fee");
    assert!(circuits_v1::ffi_verify_fee(&proof, &pi_bytes).unwrap());
    let elems = [poseidon_v1::nullifier(vk, poseidon_v1::note_hash(amount, rnd), 1), poseidon_v1::note_hash(change, change_rand)];
    let fields = V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent: 0, elements: &elems };
    assert_eq!(verify(Circuit::Fee, &proof, &encode_public_inputs_v2(Circuit::Fee, &fields).unwrap()), Ok(true));
    assert_eq!(verify(Circuit::Fee, &proof, &encode_public_inputs_v2(Circuit::Fee, &V2Fields { amount_or_fee: fee + 1, ..fields }).unwrap()), Ok(false));
}

// ─── The FFI surface itself ───────────────────────────────────────────────────────────────────────────

#[test]
fn ffi_poseidon_exports_match_the_native_functions() {
    let a = rand_fr(50);
    let b = rand_fr(51);
    let c = rand_fr(52);
    let ab = poseidon_v1::fr_to_le(&a);
    let bb = poseidon_v1::fr_to_le(&b);
    let cb = poseidon_v1::fr_to_le(&c);
    let mut out = [0u8; 32];
    assert_eq!(plonk_ffi::poseidon_hash_2(ab.as_ptr(), bb.as_ptr(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::hash_2(a, b)));
    assert_eq!(plonk_ffi::poseidon_hash_3(ab.as_ptr(), bb.as_ptr(), cb.as_ptr(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::hash_3(a, b, c)));
    assert_eq!(plonk_ffi::poseidon_note_hash(77, bb.as_ptr(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::note_hash(77, b)));
    // Non-canonical input is refused.
    let too_big = [0xffu8; 32];
    assert_eq!(plonk_ffi::poseidon_hash_2(too_big.as_ptr(), bb.as_ptr(), out.as_mut_ptr()), plonk_ffi::ERR_CRYPTO);
    // Zero hashes and root-from-path agree with the tree.
    let mut tree = FixedDepthTree::new();
    tree.push(poseidon_v1::note_hash(1, a));
    tree.push(poseidon_v1::note_hash(2, b));
    tree.push(poseidon_v1::note_hash(3, c));
    let path = tree.path(2).unwrap();
    let mut path_bytes = Vec::with_capacity(32 * TREE_DEPTH);
    for p in &path {
        path_bytes.extend_from_slice(&poseidon_v1::fr_to_le(p));
    }
    let leaf = poseidon_v1::fr_to_le(&poseidon_v1::note_hash(3, c));
    assert_eq!(plonk_ffi::merkle_root_from_path_v1(leaf.as_ptr(), 2, path_bytes.as_ptr(), path_bytes.len(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&tree.root()));
    assert_eq!(plonk_ffi::poseidon_merkle_zero(1, out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::hash_2(Fr::zero(), Fr::zero())));
    assert_eq!(plonk_ffi::poseidon_merkle_zero(33, out.as_mut_ptr()), plonk_ffi::ERR_PARAM);
}
