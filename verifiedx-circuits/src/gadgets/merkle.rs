//! Merkle path verification gadget (depth-32, Poseidon-based).
//!
//! Verifies that a given leaf (note_hash) exists in a Merkle tree
//! at the stated root, using a 32-element authentication path.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;

use super::poseidon::poseidon_hash_2;

/// Depth of the commitment Merkle tree.
pub const TREE_DEPTH: usize = 32;

/// Verify a Merkle inclusion proof in-circuit.
///
/// # Arguments
/// * `composer` — the constraint composer
/// * `leaf` — the leaf variable (note_hash)
/// * `path` — authentication path siblings (TREE_DEPTH elements)
/// * `path_indices` — direction bits (0 = left, 1 = right) as Variables
///   that are boolean-constrained
/// * `root` — the expected Merkle root (public input variable)
///
/// The gadget constrains that hashing `leaf` up the path produces `root`.
pub fn merkle_path_verify<F, P>(
    composer: &mut StandardComposer<F, P>,
    leaf: Variable,
    path: &[Variable; TREE_DEPTH],
    path_indices: &[Variable; TREE_DEPTH],
    root: Variable,
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let mut current = leaf;

    for i in 0..TREE_DEPTH {
        // Constrain path_indices[i] to be boolean (0 or 1)
        composer.boolean_gate(path_indices[i]);

        // If path_indices[i] == 0: current is left, sibling is right
        //   hash_input = (current, path[i])
        // If path_indices[i] == 1: sibling is left, current is right
        //   hash_input = (path[i], current)
        //
        // We compute both orders and select using the index bit:
        //   left  = current + path_indices[i] * (path[i] - current)
        //          = current * (1 - idx) + path[i] * idx
        //   right = path[i] + path_indices[i] * (current - path[i])
        //          = path[i] * (1 - idx) + current * idx
        let left = conditional_select(composer, path_indices[i], current, path[i]);
        let right = conditional_select(composer, path_indices[i], path[i], current);

        current = poseidon_hash_2(composer, left, right);
    }

    // Constrain computed root == expected root
    composer.assert_equal(current, root);
}

/// Conditional select: if `bit == 0` return `a`, if `bit == 1` return `b`.
///
/// Computes `result = a + bit * (b - a)` using a single arithmetic gate.
fn conditional_select<F, P>(
    composer: &mut StandardComposer<F, P>,
    bit: Variable,
    if_zero: Variable,
    if_one: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    // result = if_zero + bit * (if_one - if_zero)
    // = if_zero * (1 - bit) + if_one * bit
    //
    // We need: result = if_zero + bit * if_one - bit * if_zero
    //
    // Using arithmetic gate: q_m * a * b + q_l * a + q_r * b + q_o * c + q_c = 0
    // Let a = bit, b = if_one, c = result, and we have an auxiliary for bit * if_zero
    //
    // Simpler approach: compute diff = if_one - if_zero, then result = if_zero + bit * diff
    let diff = composer.arithmetic_gate(|gate| {
        gate.witness(if_one, if_zero, None)
            .add(F::one(), -F::one())
    });

    // product = bit * diff
    let product = composer.arithmetic_gate(|gate| {
        gate.witness(bit, diff, None).mul(F::one())
    });

    // result = if_zero + product
    let result = composer.arithmetic_gate(|gate| {
        gate.witness(if_zero, product, None)
            .add(F::one(), F::one())
    });

    result
}