//! VFX Fee Circuit (1-in / 1-out) — used by vBTC transfers
//! to pay fees from shielded VFX.
//!
//! Public inputs (in order):
//!   PI[0] = vfx_merkle_root
//!   PI[1] = fee_nullifier
//!   PI[2] = change_note_hash
//!   PI[3] = fee_scaled

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::merkle::{merkle_path_verify, TREE_DEPTH};
use crate::gadgets::note_hash::note_hash_gadget;
use crate::gadgets::nullifier::nullifier_gadget;
use crate::gadgets::range::range_check;

/// Fee circuit witness data.
#[derive(Debug, Clone)]
pub struct FeeCircuit<F: PrimeField> {
    pub input_amount_scaled: F,
    pub input_randomness: F,
    pub input_viewing_key: F,
    pub input_position: F,
    pub input_merkle_path: [F; TREE_DEPTH],
    pub input_merkle_indices: [F; TREE_DEPTH],
    pub change_amount_scaled: F,
    pub change_randomness: F,
    pub fee_scaled: F,
    pub merkle_root: F,
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for FeeCircuit<F> {
    fn default() -> Self {
        Self {
            input_amount_scaled: F::zero(),
            input_randomness: F::zero(),
            input_viewing_key: F::zero(),
            input_position: F::zero(),
            input_merkle_path: [F::zero(); TREE_DEPTH],
            input_merkle_indices: [F::zero(); TREE_DEPTH],
            change_amount_scaled: F::zero(),
            change_randomness: F::zero(),
            fee_scaled: F::zero(),
            merkle_root: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for FeeCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_FEE_CIRCUIT_V1______________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(4);

        let root_var = composer.add_input(self.merkle_root);

        // Fee
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // Input
        let in_amount_var = composer.add_input(self.input_amount_scaled);
        let in_rand_var = composer.add_input(self.input_randomness);
        let in_vk_var = composer.add_input(self.input_viewing_key);
        let in_pos_var = composer.add_input(self.input_position);

        let mut path_vars = [composer.zero_var(); TREE_DEPTH];
        let mut idx_vars = [composer.zero_var(); TREE_DEPTH];
        for j in 0..TREE_DEPTH {
            path_vars[j] = composer.add_input(self.input_merkle_path[j]);
            idx_vars[j] = composer.add_input(self.input_merkle_indices[j]);
        }

        let in_note_hash = note_hash_gadget(composer, in_amount_var, in_rand_var);
        let in_nullifier = nullifier_gadget(composer, in_vk_var, in_note_hash, in_pos_var);

        merkle_path_verify(composer, in_note_hash, &path_vars, &idx_vars, root_var);
        range_check(composer, in_amount_var);

        // Change output
        let ch_amount_var = composer.add_input(self.change_amount_scaled);
        let ch_rand_var = composer.add_input(self.change_randomness);
        let ch_note_hash = note_hash_gadget(composer, ch_amount_var, ch_rand_var);
        range_check(composer, ch_amount_var);

        // Balance: input = change + fee
        let change_plus_fee = composer.arithmetic_gate(|gate| {
            gate.witness(ch_amount_var, fee_var, None)
                .add(F::one(), F::one())
        });
        composer.assert_equal(in_amount_var, change_plus_fee);

        // Public inputs
        let n = composer.circuit_bound();
        composer.constrain_to_constant(root_var, F::zero(), F::zero());
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(in_nullifier, F::zero(), F::zero());
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(ch_note_hash, F::zero(), F::zero());
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), F::zero());
        pi_positions.push(n);

        self.pi_pos = pi_positions;

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 14 // 16384
    }
}