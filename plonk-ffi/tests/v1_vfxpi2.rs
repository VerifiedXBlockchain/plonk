//! End-to-end tests of the v2 owner-bound circuits against the on-chain public-input encoding (VFXPI1 version 3)
//! and the circuit-compatible native Poseidon. They need the `VXPLNK06` params with prover keys: set
//! `VFX_PLONK_PARAMS` to the file, or place `vfx_plonk_v4.params` in the workspace root. Without it every test
//! here returns early (and says so), so `cargo test` stays green on machines without the file.
//!
//! What they pin down for the Core node and wallet:
//!  - `poseidon_owner_pk` / `poseidon_note_hash_v2` / `poseidon_hash_2` / `poseidon_hash_3` equal the circuits;
//!  - a fixed-depth-32 tree with `poseidon_merkle_zero` padding is the tree the circuits accept;
//!  - a proof verifies against a VFXPI1 v3 blob built from on-chain fields, and not against a tampered one;
//!  - a one-note spend uses the public dummy note (amount 0, randomness 0, nullifier key 0) as its second input;
//!  - (re-audit) a note cannot be spent with another nullifier key, and an unshield cannot be redirected.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use plonk_ffi::circuits_v1;
use plonk_ffi::poseidon_v1::{self, FixedDepthTree, TREE_DEPTH};
use plonk_ffi::vfxpi1::{self, encode_public_inputs_v3, Circuit, V2Fields};
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
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("vfx_plonk_v4.params");
            p.exists().then(|| p.to_string_lossy().into_owned())
        });
        let Some(path) = path else {
            eprintln!("v1_vfxpi2: no params file (set VFX_PLONK_PARAMS); tests skipped");
            return;
        };
        let bytes = std::fs::read(&path).expect("read params");
        circuits_v1::try_load_v1_params(&bytes).expect("load VXPLNK06");
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
    circuits_v1::ffi_verify_vfxpi3(circuit as u8, proof, pi_blob)
}

/// Field-element little-endian bytes made from a seed (always canonical).
fn rand_fr(seed: u64) -> Fr {
    poseidon_v1::hash_2(fr(seed), fr(0xC0FFEE))
}

/// A note as the v2 circuits see it: (amount, randomness, owner's nullifier key).
struct Note {
    amount: u64,
    randomness: Fr,
    nk: Fr,
}

impl Note {
    fn owner_pk(&self) -> Fr {
        poseidon_v1::owner_pk(self.nk)
    }
    fn hash(&self) -> Fr {
        poseidon_v1::note_hash_v2(self.amount, self.randomness, self.owner_pk())
    }
    fn nullifier(&self, position: u64) -> Fr {
        poseidon_v1::nullifier(self.nk, self.hash(), position)
    }
}

/// The public dummy note: amount 0, randomness 0, nullifier key 0.
fn dummy() -> Note {
    Note { amount: 0, randomness: Fr::zero(), nk: Fr::zero() }
}

fn input(tree: &FixedDepthTree, position: u64, note: &Note, nk: Fr) -> TransferInput<Fr> {
    let path = tree.path(position).expect("path");
    let mut indices = [Fr::zero(); TREE_DEPTH];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = fr((position >> i) & 1);
    }
    TransferInput { amount_scaled: fr(note.amount), randomness: note.randomness, nullifier_key: nk, position: fr(position), merkle_path: path, merkle_indices: indices }
}

fn output(amount: u64, randomness: Fr, owner_pk: Fr) -> TransferOutput<Fr> {
    TransferOutput { amount_scaled: fr(amount), randomness, owner_pk }
}

fn unshield_circuit(tree: &FixedDepthTree, ins: [(u64, &Note, Fr); 2], transparent: u64, change: &Note, fee: u64, recipient: Fr) -> UnshieldCircuit<Fr> {
    UnshieldCircuit {
        inputs: [input(tree, ins[0].0, ins[0].1, ins[0].2), input(tree, ins[1].0, ins[1].1, ins[1].2)],
        transparent_amount_scaled: fr(transparent),
        change_amount_scaled: fr(change.amount),
        change_randomness: change.randomness,
        change_owner_pk: change.owner_pk(),
        fee_scaled: fr(fee),
        merkle_root: tree.root(),
        recipient_tag: recipient,
        pi_pos: Vec::new(),
    }
}

fn unshield_blob(root: Fr, fee: u64, transparent: u64, null0: Fr, null1: Fr, change_hash: Fr, recipient: Fr) -> Vec<u8> {
    let elems = [null0, null1, change_hash, recipient];
    encode_public_inputs_v3(Circuit::Unshield, &V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent, elements: &elems }).unwrap()
}

// ─── Poseidon equality with the circuits ──────────────────────────────────────────────────────────────

#[test]
fn native_note_hash_equals_the_circuits() {
    if !params_loaded() { return; }
    let amount = 100_000_000u64;
    let randomness = rand_fr(1);
    let owner = poseidon_v1::owner_pk(rand_fr(2));
    let (proof, pi_bytes) = circuits_v1::ffi_prove_shield(amount, randomness, owner).expect("prove shield");
    // The prover's own encoding lists the circuit's public inputs, negated: [-amount, -note_hash].
    let pi = circuit_keys::deserialize_public_inputs(&pi_bytes).expect("pi");
    let vals: Vec<Fr> = pi.get_vals().copied().collect();
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], -fr(amount));
    assert_eq!(vals[1], -poseidon_v1::note_hash_v2(amount, randomness, owner), "native Poseidon is not the circuits' Poseidon");
    let pos: Vec<usize> = pi.get_pos().copied().collect();
    assert_eq!(pos, circuits_v1::pi_positions(Circuit::Shield));
    assert!(circuits_v1::ffi_verify_shield(&proof, &pi_bytes).unwrap());
}

// ─── Shield ───────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn shield_verifies_against_vfxpi3_and_refuses_tampering() {
    if !params_loaded() { return; }
    let amount = 250_000_000u64;
    let note = Note { amount, randomness: rand_fr(2), nk: rand_fr(3) };
    let (proof, _) = circuits_v1::ffi_prove_shield(amount, note.randomness, note.owner_pk()).unwrap();
    let note_hash = [note.hash()];
    let fields = V2Fields { asset_tag: [7u8; 32], merkle_root: Fr::zero(), amount_or_fee: amount, transparent: 0, elements: &note_hash };
    let blob = encode_public_inputs_v3(Circuit::Shield, &fields).unwrap();
    assert_eq!(verify(Circuit::Shield, &proof, &blob), Ok(true));

    // Another amount, another owner's note hash, the wrong circuit byte, a version-2 blob: all refused.
    let other_amount = V2Fields { amount_or_fee: amount + 1, ..fields };
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v3(Circuit::Shield, &other_amount).unwrap()), Ok(false));
    let other_owner = [poseidon_v1::note_hash_v2(amount, note.randomness, poseidon_v1::owner_pk(rand_fr(4)))];
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v3(Circuit::Shield, &V2Fields { elements: &other_owner, ..fields }).unwrap()), Ok(false));
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Err(plonk_ffi::ERR_PARAM));
    let v2_blob = vfxpi1::encode_public_inputs_v2(Circuit::Shield, &fields).unwrap();
    assert_eq!(verify(Circuit::Shield, &proof, &v2_blob), Err(plonk_ffi::ERR_PARAM));
    assert_eq!(plonk_ffi::plonk_verify(Circuit::Shield as u8, proof.as_ptr(), proof.len(), v2_blob.as_ptr(), v2_blob.len()), plonk_ffi::ERR_PARAM);
    assert_eq!(plonk_ffi::plonk_verify(Circuit::Shield as u8, proof.as_ptr(), proof.len(), blob.as_ptr(), blob.len()), 1);
    // The asset tag is not a circuit input: the same proof verifies under any tag (it is bound by the tx hash).
    let other_tag = V2Fields { asset_tag: [1u8; 32], ..fields };
    assert_eq!(verify(Circuit::Shield, &proof, &encode_public_inputs_v3(Circuit::Shield, &other_tag).unwrap()), Ok(true));
}

// ─── Unshield with the fixed-depth tree ───────────────────────────────────────────────────────────────

#[test]
fn unshield_two_notes_verifies_against_vfxpi3_built_from_the_tree() {
    if !params_loaded() { return; }
    let nk = rand_fr(10);
    let notes = [
        Note { amount: 300_000_000, randomness: rand_fr(11), nk },
        Note { amount: 200_000_000, randomness: rand_fr(12), nk },
        Note { amount: 50_000_000, randomness: rand_fr(13), nk: rand_fr(99) },
    ];
    let mut tree = FixedDepthTree::new();
    for n in &notes {
        tree.push(n.hash());
    }
    let root = tree.root();
    let fee = 300u64;
    let transparent = 400_000_000u64;
    let change = Note { amount: notes[0].amount + notes[1].amount - transparent - fee, randomness: rand_fr(14), nk };
    let recipient = rand_fr(15);

    let mut circuit = unshield_circuit(&tree, [(0, &notes[0], nk), (1, &notes[1], nk)], transparent, &change, fee, recipient);
    let (proof, pi_bytes) = circuits_v1::ffi_prove_unshield(&mut circuit).expect("prove unshield");
    assert!(circuits_v1::ffi_verify_unshield(&proof, &pi_bytes).unwrap(), "prover's own public inputs");

    let blob = unshield_blob(root, fee, transparent, notes[0].nullifier(0), notes[1].nullifier(1), change.hash(), recipient);
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Ok(true), "VFXPI1 v3 built from native tree, nullifiers, change hash and recipient");

    // The prover's encoding and the rebuilt one carry the same values at the same positions.
    let pi = circuit_keys::deserialize_public_inputs(&pi_bytes).unwrap();
    let rebuilt = circuit_keys::public_inputs_from_values(&circuits_v1::pi_positions(Circuit::Unshield), &vfxpi1::parse_public_inputs_v3(&blob).unwrap().values).unwrap();
    assert_eq!(pi, rebuilt);

    // A different transparent amount or a wrong root is refused.
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(root, fee, transparent + 1, notes[0].nullifier(0), notes[1].nullifier(1), change.hash(), recipient)), Ok(false));
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(fr(1), fee, transparent, notes[0].nullifier(0), notes[1].nullifier(1), change.hash(), recipient)), Ok(false));
}

#[test]
fn unshield_one_note_uses_the_public_dummy_note() {
    if !params_loaded() { return; }
    // Convention for the node: leaf 0 of every tree is the public dummy note (amount 0, randomness 0, owner key of
    // nullifier key 0). Its nullifier is one public constant that consensus never records.
    let nk = rand_fr(20);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let note = Note { amount: 120_000_000, randomness: rand_fr(21), nk };
    tree.push(note.hash());
    let fee = 300u64;
    let transparent = 100_000_000u64;
    let change = Note { amount: note.amount - transparent - fee, randomness: rand_fr(22), nk };
    let recipient = rand_fr(23);
    let mut circuit = unshield_circuit(&tree, [(1, &note, nk), (0, &d, Fr::zero())], transparent, &change, fee, recipient);
    let (proof, _) = circuits_v1::ffi_prove_unshield(&mut circuit).expect("prove");
    let blob = unshield_blob(tree.root(), fee, transparent, note.nullifier(1), d.nullifier(0), change.hash(), recipient);
    assert_eq!(verify(Circuit::Unshield, &proof, &blob), Ok(true));
    // The dummy's nullifier is the same for every spender.
    assert_eq!(d.nullifier(0), poseidon_v1::nullifier(Fr::zero(), poseidon_v1::note_hash_v2(0, Fr::zero(), poseidon_v1::owner_pk(Fr::zero())), 0));
}

// ─── Re-audit: the two holes the v1 circuits had ──────────────────────────────────────────────────────

/// Finding 1(a): with v1 anyone who knew (amount, randomness, position) could spend a note with any key and get a
/// fresh nullifier each time. With v2 the note names its owner: a spend with another nullifier key does not verify.
#[test]
fn a_note_cannot_be_spent_with_another_nullifier_key() {
    if !params_loaded() { return; }
    let owner_nk = rand_fr(30);
    let thief_nk = rand_fr(31);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let note = Note { amount: 1_000_000_000, randomness: rand_fr(32), nk: owner_nk }; // the thief knows amount + randomness
    tree.push(note.hash());
    let fee = 300u64;
    let transparent = 900_000_000u64;
    let change_amount = note.amount - transparent - fee;
    let recipient = rand_fr(33);

    // The owner's spend verifies.
    let change = Note { amount: change_amount, randomness: rand_fr(34), nk: owner_nk };
    let mut honest = unshield_circuit(&tree, [(1, &note, owner_nk), (0, &d, Fr::zero())], transparent, &change, fee, recipient);
    let (proof, _) = circuits_v1::ffi_prove_unshield(&mut honest).expect("owner proves");
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(tree.root(), fee, transparent, note.nullifier(1), d.nullifier(0), change.hash(), recipient)), Ok(true));

    // The thief's spend of the same note (its own nullifier key, its own change note) cannot be made to verify:
    // the circuit recomputes the note hash from the thief's key, so the Merkle membership fails.
    let thief_change = Note { amount: change_amount, randomness: rand_fr(35), nk: thief_nk };
    let mut theft = unshield_circuit(&tree, [(1, &note, thief_nk), (0, &d, Fr::zero())], transparent, &thief_change, fee, recipient);
    let thief_nullifier = poseidon_v1::nullifier(thief_nk, note.hash(), 1);
    let blob = unshield_blob(tree.root(), fee, transparent, thief_nullifier, d.nullifier(0), thief_change.hash(), recipient);
    match circuits_v1::ffi_prove_unshield(&mut theft) {
        Err(_) => {} // the prover refused an unsatisfied circuit
        Ok((stolen_proof, _)) => {
            assert_ne!(verify(Circuit::Unshield, &stolen_proof, &blob), Ok(true), "a non-owner's spend verified");
            // Nor does it verify against the nullifier the circuit would compute from the forged note hash.
            let forged_hash = poseidon_v1::note_hash_v2(note.amount, note.randomness, poseidon_v1::owner_pk(thief_nk));
            let forged_nullifier = poseidon_v1::nullifier(thief_nk, forged_hash, 1);
            assert_ne!(verify(Circuit::Unshield, &stolen_proof, &unshield_blob(tree.root(), fee, transparent, forged_nullifier, d.nullifier(0), thief_change.hash(), recipient)), Ok(true));
        }
    }
}

/// A spend's position is its Merkle path's direction bits read as a number. The position feeds the nullifier, so a
/// position free of the path let one note be spent under as many nullifiers as positions. A spend that keeps the real
/// path but claims another position cannot be proven or verified; the honest spend of the same note verifies.
#[test]
fn a_spend_position_is_its_merkle_path() {
    if !params_loaded() { return; }
    let nk = rand_fr(40);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let note = Note { amount: 1_000_000_000, randomness: rand_fr(41), nk };
    tree.push(note.hash());
    let fee = 300u64;
    let transparent = 900_000_000u64;
    let change = Note { amount: note.amount - transparent - fee, randomness: rand_fr(42), nk };
    let recipient = rand_fr(43);

    let mut honest = unshield_circuit(&tree, [(1, &note, nk), (0, &d, Fr::zero())], transparent, &change, fee, recipient);
    let (proof, _) = circuits_v1::ffi_prove_unshield(&mut honest).expect("honest spend proves");
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(tree.root(), fee, transparent, note.nullifier(1), d.nullifier(0), change.hash(), recipient)), Ok(true));

    for claimed in [1u64 + (1u64 << 32), 3u64] {
        let mut forged = unshield_circuit(&tree, [(1, &note, nk), (0, &d, Fr::zero())], transparent, &change, fee, recipient);
        forged.inputs[0].position = fr(claimed);
        let blob = unshield_blob(tree.root(), fee, transparent, note.nullifier(claimed), d.nullifier(0), change.hash(), recipient);
        match circuits_v1::ffi_prove_unshield(&mut forged) {
            Err(_) => {} // the prover refused an unsatisfied circuit
            Ok((forged_proof, _)) => assert_ne!(verify(Circuit::Unshield, &forged_proof, &blob), Ok(true), "a spend at position {claimed} verified"),
        }
    }
}

/// Finding 1(b): with v1 the transparent recipient was not a public input, so a finished unshield could be copied with
/// another `ToAddress`. With v2 the recipient tag is public input 7 and the proof fails for any other recipient.
#[test]
fn an_unshield_cannot_be_redirected() {
    if !params_loaded() { return; }
    let nk = rand_fr(40);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let note = Note { amount: 500_000_000, randomness: rand_fr(41), nk };
    tree.push(note.hash());
    let fee = 300u64;
    let transparent = 400_000_000u64;
    let change = Note { amount: note.amount - transparent - fee, randomness: rand_fr(42), nk };
    let alice = rand_fr(43);
    let mallory = rand_fr(44);
    let mut circuit = unshield_circuit(&tree, [(1, &note, nk), (0, &d, Fr::zero())], transparent, &change, fee, alice);
    let (proof, _) = circuits_v1::ffi_prove_unshield(&mut circuit).expect("prove");
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(tree.root(), fee, transparent, note.nullifier(1), d.nullifier(0), change.hash(), alice)), Ok(true));
    assert_eq!(verify(Circuit::Unshield, &proof, &unshield_blob(tree.root(), fee, transparent, note.nullifier(1), d.nullifier(0), change.hash(), mallory)), Ok(false), "redirected unshield verified");
}

/// A transfer output names its recipient through the owner key in the note hash: the recipient (and only the
/// recipient) can spend it in turn.
#[test]
fn transfer_output_belongs_to_its_recipient() {
    if !params_loaded() { return; }
    let alice = rand_fr(50);
    let bob = rand_fr(51);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let ins = [Note { amount: 500_000_000, randomness: rand_fr(52), nk: alice }, Note { amount: 100_000_000, randomness: rand_fr(53), nk: alice }];
    for n in &ins {
        tree.push(n.hash());
    }
    let root = tree.root();
    let fee = 300u64;
    let to_bob = Note { amount: 350_000_000, randomness: rand_fr(54), nk: bob };
    let change = Note { amount: ins[0].amount + ins[1].amount - to_bob.amount - fee, randomness: rand_fr(55), nk: alice };
    let mut circuit = TransferCircuit {
        inputs: [input(&tree, 1, &ins[0], alice), input(&tree, 2, &ins[1], alice)],
        outputs: [output(to_bob.amount, to_bob.randomness, to_bob.owner_pk()), output(change.amount, change.randomness, change.owner_pk())],
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, pi_bytes) = circuits_v1::ffi_prove_transfer(&mut circuit).expect("prove transfer");
    assert!(circuits_v1::ffi_verify_transfer(&proof, &pi_bytes).unwrap());
    let elems = [ins[0].nullifier(1), ins[1].nullifier(2), to_bob.hash(), change.hash()];
    let fields = V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent: 0, elements: &elems };
    assert_eq!(verify(Circuit::Transfer, &proof, &encode_public_inputs_v3(Circuit::Transfer, &fields).unwrap()), Ok(true));
    // Swapped nullifiers, or Bob's note re-addressed to Alice: refused.
    let swapped = [elems[1], elems[0], elems[2], elems[3]];
    assert_eq!(verify(Circuit::Transfer, &proof, &encode_public_inputs_v3(Circuit::Transfer, &V2Fields { elements: &swapped, ..fields }).unwrap()), Ok(false));
    let readdressed = [elems[0], elems[1], poseidon_v1::note_hash_v2(to_bob.amount, to_bob.randomness, poseidon_v1::owner_pk(alice)), elems[3]];
    assert_eq!(verify(Circuit::Transfer, &proof, &encode_public_inputs_v3(Circuit::Transfer, &V2Fields { elements: &readdressed, ..fields }).unwrap()), Ok(false));

    // Bob spends his note (after it lands in the tree); Alice, who built it and knows its randomness, cannot.
    tree.push(to_bob.hash());
    tree.push(change.hash());
    let payout = Note { amount: to_bob.amount - 300_000_000 - fee, randomness: rand_fr(56), nk: bob };
    let mut bob_spend = unshield_circuit(&tree, [(3, &to_bob, bob), (0, &d, Fr::zero())], 300_000_000, &payout, fee, rand_fr(57));
    let (bob_proof, _) = circuits_v1::ffi_prove_unshield(&mut bob_spend).expect("bob proves");
    assert_eq!(verify(Circuit::Unshield, &bob_proof, &unshield_blob(tree.root(), fee, 300_000_000, to_bob.nullifier(3), d.nullifier(0), payout.hash(), rand_fr(57))), Ok(true));
    let alice_payout = Note { amount: payout.amount, randomness: rand_fr(58), nk: alice };
    let mut alice_steals = unshield_circuit(&tree, [(3, &to_bob, alice), (0, &d, Fr::zero())], 300_000_000, &alice_payout, fee, rand_fr(59));
    if let Ok((stolen, _)) = circuits_v1::ffi_prove_unshield(&mut alice_steals) {
        let alice_nullifier = poseidon_v1::nullifier(alice, to_bob.hash(), 3);
        assert_ne!(verify(Circuit::Unshield, &stolen, &unshield_blob(tree.root(), fee, 300_000_000, alice_nullifier, d.nullifier(0), alice_payout.hash(), rand_fr(59))), Ok(true));
    }
}

// ─── Fee ──────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn fee_verifies_against_vfxpi3() {
    if !params_loaded() { return; }
    let nk = rand_fr(60);
    let d = dummy();
    let mut tree = FixedDepthTree::new();
    tree.push(d.hash());
    let note = Note { amount: 5_000_000, randomness: rand_fr(61), nk };
    tree.push(note.hash());
    let root = tree.root();
    let fee = 300u64;
    let change = Note { amount: note.amount - fee, randomness: rand_fr(62), nk };
    let inp = input(&tree, 1, &note, nk);
    let mut circuit = FeeCircuit {
        input_amount_scaled: fr(note.amount),
        input_randomness: note.randomness,
        input_nullifier_key: nk,
        input_position: fr(1),
        input_merkle_path: inp.merkle_path,
        input_merkle_indices: inp.merkle_indices,
        change_amount_scaled: fr(change.amount),
        change_randomness: change.randomness,
        change_owner_pk: change.owner_pk(),
        fee_scaled: fr(fee),
        merkle_root: root,
        pi_pos: Vec::new(),
    };
    let (proof, pi_bytes) = circuits_v1::ffi_prove_fee(&mut circuit).expect("prove fee");
    assert!(circuits_v1::ffi_verify_fee(&proof, &pi_bytes).unwrap());
    let elems = [note.nullifier(1), change.hash()];
    let fields = V2Fields { asset_tag: [0u8; 32], merkle_root: root, amount_or_fee: fee, transparent: 0, elements: &elems };
    assert_eq!(verify(Circuit::Fee, &proof, &encode_public_inputs_v3(Circuit::Fee, &fields).unwrap()), Ok(true));
    assert_eq!(verify(Circuit::Fee, &proof, &encode_public_inputs_v3(Circuit::Fee, &V2Fields { amount_or_fee: fee + 1, ..fields }).unwrap()), Ok(false));
}

// ─── The FFI surface itself ───────────────────────────────────────────────────────────────────────────

/// The C entry point the node uses (`plonk_load_params`) must take the VXPLNK06 file and report the v2 bits, and must
/// refuse VXPLNK03 (ownerless circuits) and VXPLNK04 (seeded setup) files. (Stage 3 regression: the dispatcher once matched the old magic only, so the new file "loaded"
/// without loading any circuit.)
#[test]
fn plonk_load_params_takes_vxplnk06_and_reports_the_v2_capabilities() {
    let Some(path) = std::env::var("VFX_PLONK_PARAMS").ok().filter(|p| std::path::Path::new(p).exists()) else {
        eprintln!("plonk_load_params test: no VFX_PLONK_PARAMS; skipped");
        return;
    };
    let c_path = std::ffi::CString::new(path.clone()).unwrap();
    assert_eq!(plonk_ffi::plonk_load_params(c_path.as_ptr()), plonk_ffi::SUCCESS);
    let caps = plonk_ffi::plonk_capabilities();
    assert_ne!(caps & plonk_ffi::PLONK_CAP_V1_CIRCUITS, 0);
    assert_ne!(caps & plonk_ffi::PLONK_CAP_VFXPI2_VERIFY, 0);
    assert_ne!(caps & plonk_ffi::PLONK_CAP_V2_CIRCUITS, 0);
    assert_ne!(caps & plonk_ffi::PLONK_CAP_V1_PROVE, 0, "the params carry prover keys");
    // A VXPLNK03 header (the v1 circuits), a VXPLNK04 header (the seeded, forgeable setup) and a VXPLNK05 header (spend
    // position not bound to the Merkle path) are refused.
    let mut old = std::fs::read(&path).unwrap();
    for magic in [b"VXPLNK03", b"VXPLNK04", b"VXPLNK05"] {
        old[..8].copy_from_slice(magic);
        let tmp = std::env::temp_dir().join("vfx_plonk_rejected.params");
        std::fs::write(&tmp, &old).unwrap();
        let c_tmp = std::ffi::CString::new(tmp.to_string_lossy().into_owned()).unwrap();
        assert_eq!(plonk_ffi::plonk_load_params(c_tmp.as_ptr()), plonk_ffi::ERR_CRYPTO, "{:?}", std::str::from_utf8(magic));
        let _ = std::fs::remove_file(&tmp);
    }
    // Re-load the real file so later tests in this process keep working.
    assert_eq!(plonk_ffi::plonk_load_params(c_path.as_ptr()), plonk_ffi::SUCCESS);
}

#[test]
fn ffi_poseidon_exports_match_the_native_functions() {
    let a = rand_fr(70);
    let b = rand_fr(71);
    let c = rand_fr(72);
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
    // v2: owner key and owner-bound note hash.
    assert_eq!(plonk_ffi::poseidon_owner_pk(ab.as_ptr(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::owner_pk(a)));
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::hash_2(fr(poseidon_v1::OWNER_PK_DOMAIN), a)));
    let owner = out;
    assert_eq!(plonk_ffi::poseidon_note_hash_v2(77, bb.as_ptr(), owner.as_ptr(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::note_hash_v2(77, b, poseidon_v1::owner_pk(a))));
    assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::hash_3(fr(77), b, poseidon_v1::owner_pk(a))));
    // Non-canonical input is refused.
    let too_big = [0xffu8; 32];
    assert_eq!(plonk_ffi::poseidon_hash_2(too_big.as_ptr(), bb.as_ptr(), out.as_mut_ptr()), plonk_ffi::ERR_CRYPTO);
    assert_eq!(plonk_ffi::poseidon_owner_pk(too_big.as_ptr(), out.as_mut_ptr()), plonk_ffi::ERR_CRYPTO);
    assert_eq!(plonk_ffi::poseidon_note_hash_v2(1, bb.as_ptr(), too_big.as_ptr(), out.as_mut_ptr()), plonk_ffi::ERR_CRYPTO);
    // Zero hashes and root-from-path agree with the tree.
    let mut tree = FixedDepthTree::new();
    tree.push(poseidon_v1::note_hash_v2(1, a, poseidon_v1::owner_pk(c)));
    tree.push(poseidon_v1::note_hash_v2(2, b, poseidon_v1::owner_pk(c)));
    tree.push(poseidon_v1::note_hash_v2(3, c, poseidon_v1::owner_pk(c)));
    let path = tree.path(2).unwrap();
    let mut path_bytes = Vec::with_capacity(32 * TREE_DEPTH);
    for p in &path {
        path_bytes.extend_from_slice(&poseidon_v1::fr_to_le(p));
    }
    let leaf = poseidon_v1::fr_to_le(&poseidon_v1::note_hash_v2(3, c, poseidon_v1::owner_pk(c)));
    assert_eq!(plonk_ffi::merkle_root_from_path_v1(leaf.as_ptr(), 2, path_bytes.as_ptr(), path_bytes.len(), out.as_mut_ptr()), plonk_ffi::SUCCESS);
    assert_eq!(out, poseidon_v1::fr_to_le(&tree.root()));
    for level in 0..=TREE_DEPTH as u32 {
        assert_eq!(plonk_ffi::poseidon_merkle_zero(level, out.as_mut_ptr()), plonk_ffi::SUCCESS);
        assert_eq!(out, poseidon_v1::fr_to_le(&poseidon_v1::zero_hashes()[level as usize]));
    }
    assert_eq!(plonk_ffi::poseidon_merkle_zero(TREE_DEPTH as u32 + 1, out.as_mut_ptr()), plonk_ffi::ERR_PARAM);
    // The capability bit for the v2 circuits is reported once params are loaded.
    if params_loaded() {
        assert_ne!(plonk_ffi::plonk_capabilities() & plonk_ffi::PLONK_CAP_V2_CIRCUITS, 0);
    }
}
