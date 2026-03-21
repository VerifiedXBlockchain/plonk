//! Unshield Circuit (Z→T) — proves ownership of shielded inputs
//! and outputs a transparent amount.
//!
//! Public inputs (in order):
//!   PI[0] = merkle_root
//!   PI[1] = nullifier_0
//!   PI[2] = nullifier_1
//!   PI[3] = transparent_amount (scaled)
//!   PI[4] = change_note_hash
//!   PI[5] = fee_scaled

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::merkle::{merkle_path_verify, TREE_DEPTH};
use crate::gadgets::note_hash::note_hash_gadget;
use crate::gadgets::nullifier::nullifier_gadget;
use crate::gadgets::range::range_check;

use super::transfer::TransferInput;

/// Unshield circuit witness data.
#[derive(Debug, Clone)]
pub struct UnshieldCircuit<F: PrimeField> {
    pub inputs: [TransferInput<F>; 2],
    pub transparent_amount_scaled: F,
    pub change_amount_scaled: F,
    pub change_randomness: F,
    pub fee_scaled: F,
    pub merkle_root: F,
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for UnshieldCircuit<F> {
    fn default() -> Self {
        Self {
            inputs: [TransferInput::default(), TransferInput::default()],
            transparent_amount_scaled: F::zero(),
            change_amount_scaled: F::zero(),
            change_randomness: F::zero(),
            fee_scaled: F::zero(),
            merkle_root: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for UnshieldCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_UNSHIELD_CIRCUIT_V1_________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(6);

        let root_var = composer.add_input(self.merkle_root);

        // Fee
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // Transparent amount
        let transparent_var = composer.add_input(self.transparent_amount_scaled);
        range_check(composer, transparent_var);

        // Process inputs
        let mut input_amount_vars = Vec::with_capacity(2);
        let mut nullifier_vars = Vec::with_capacity(2);

        for i in 0..2 {
            let inp = &self.inputs[i];
            let amount_var = composer.add_input(inp.amount_scaled);
            let randomness_var = composer.add_input(inp.randomness);
            let vk_var = composer.add_input(inp.viewing_key);
            let pos_var = composer.add_input(inp.position);

            let mut path_vars = [composer.zero_var(); TREE_DEPTH];
            let mut idx_vars = [composer.zero_var(); TREE_DEPTH];
            for j in 0..TREE_DEPTH {
                path_vars[j] = composer.add_input(inp.merkle_path[j]);
                idx_vars[j] = composer.add_input(inp.merkle_indices[j]);
            }

            let note_hash = note_hash_gadget(composer, amount_var, randomness_var);
            let nullifier = nullifier_gadget(composer, vk_var, note_hash, pos_var);
            nullifier_vars.push(nullifier);

            merkle_path_verify(composer, note_hash, &path_vars, &idx_vars, root_var);

            range_check(composer, amount_var);
            input_amount_vars.push(amount_var);
        }

        // Change output
        let change_amount_var = composer.add_input(self.change_amount_scaled);
        let change_randomness_var = composer.add_input(self.change_randomness);
        let change_note_hash = note_hash_gadget(composer, change_amount_var, change_randomness_var);
        range_check(composer, change_amount_var);

        // Balance: sum(inputs) = transparent + change + fee
        let sum_inputs = composer.arithmetic_gate(|gate| {
            gate.witness(input_amount_vars[0], input_amount_vars[1], None)
                .add(F::one(), F::one())
        });

        let sum_outputs = composer.arithmetic_gate(|gate| {
            gate.witness(transparent_var, change_amount_var, None)
                .add(F::one(), F::one())
        });

        let sum_outputs_plus_fee = composer.arithmetic_gate(|gate| {
            gate.witness(sum_outputs, fee_var, None)
                .add(F::one(), F::one())
        });

        composer.assert_equal(sum_inputs, sum_outputs_plus_fee);

        // Public inputs
        let n = composer.circuit_bound();
        composer.constrain_to_constant(root_var, F::zero(), Some(F::zero()));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[0], F::zero(), Some(F::zero()));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[1], F::zero(), Some(F::zero()));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(transparent_var, F::zero(), Some(F::zero()));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(change_note_hash, F::zero(), Some(F::zero()));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), Some(F::zero()));
        pi_positions.push(n);

        self.pi_pos = pi_positions;

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 15 // 32768
    }
}