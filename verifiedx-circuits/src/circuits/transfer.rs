//! Transfer Circuit (2-in / 2-out, Z→Z).
//!
//! Public inputs (in order):
//!   PI[0] = merkle_root
//!   PI[1] = nullifier_0
//!   PI[2] = nullifier_1
//!   PI[3] = output_note_hash_0
//!   PI[4] = output_note_hash_1
//!   PI[5] = fee_scaled
//!
//! Constraints:
//!   For each input i:
//!     1. note_hash_i = Poseidon(amount_i, randomness_i)
//!     2. nullifier_i = Poseidon(viewing_key_i, note_hash_i, position_i)
//!     3. nullifier_i == PI nullifier_i
//!     4. Merkle path from note_hash_i to root is valid
//!     5. range_check(amount_i)
//!   For each output j:
//!     6. out_note_hash_j = Poseidon(out_amount_j, out_randomness_j)
//!     7. out_note_hash_j == PI output_note_hash_j
//!     8. range_check(out_amount_j)
//!   Balance:
//!     9. sum(input_amounts) = sum(output_amounts) + fee

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::merkle::{merkle_path_verify, TREE_DEPTH};
use crate::gadgets::note_hash::note_hash_gadget;
use crate::gadgets::nullifier::nullifier_gadget;
use crate::gadgets::range::range_check;

/// Per-input witness data for the transfer circuit.
#[derive(Debug, Clone)]
pub struct TransferInput<F: PrimeField> {
    pub amount_scaled: F,
    pub randomness: F,
    pub viewing_key: F,
    pub position: F,
    pub merkle_path: [F; TREE_DEPTH],
    pub merkle_indices: [F; TREE_DEPTH],
}

impl<F: PrimeField> Default for TransferInput<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
            viewing_key: F::zero(),
            position: F::zero(),
            merkle_path: [F::zero(); TREE_DEPTH],
            merkle_indices: [F::zero(); TREE_DEPTH],
        }
    }
}

/// Per-output witness data.
#[derive(Debug, Clone)]
pub struct TransferOutput<F: PrimeField> {
    pub amount_scaled: F,
    pub randomness: F,
}

impl<F: PrimeField> Default for TransferOutput<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
        }
    }
}

/// The Merkle root witness (shared by both inputs).
#[derive(Debug, Clone)]
pub struct TransferCircuit<F: PrimeField> {
    pub inputs: [TransferInput<F>; 2],
    pub outputs: [TransferOutput<F>; 2],
    pub fee_scaled: F,
    /// The expected Merkle root (provided as witness, constrained as PI).
    pub merkle_root: F,
    /// Gate indices for public inputs (filled by gadget).
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for TransferCircuit<F> {
    fn default() -> Self {
        Self {
            inputs: [TransferInput::default(), TransferInput::default()],
            outputs: [TransferOutput::default(), TransferOutput::default()],
            fee_scaled: F::zero(),
            merkle_root: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for TransferCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_TRANSFER_CIRCUIT_V1_________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(6);

        // Merkle root as a witness variable (will be constrained as PI)
        let root_var = composer.add_input(self.merkle_root);

        // === Process inputs ===
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

            // note_hash = Poseidon(amount, randomness)
            let note_hash = note_hash_gadget(composer, amount_var, randomness_var);

            // nullifier = Poseidon(viewing_key, note_hash, position)
            let nullifier = nullifier_gadget(composer, vk_var, note_hash, pos_var);
            nullifier_vars.push(nullifier);

            // Merkle path verification against shared root
            merkle_path_verify(composer, note_hash, &path_vars, &idx_vars, root_var);

            // Range check
            range_check(composer, amount_var);

            input_amount_vars.push(amount_var);
        }

        // === Process outputs ===
        let mut output_amount_vars = Vec::with_capacity(2);
        let mut output_note_hash_vars = Vec::with_capacity(2);

        for j in 0..2 {
            let out = &self.outputs[j];

            let amount_var = composer.add_input(out.amount_scaled);
            let randomness_var = composer.add_input(out.randomness);

            let note_hash = note_hash_gadget(composer, amount_var, randomness_var);
            range_check(composer, amount_var);

            output_amount_vars.push(amount_var);
            output_note_hash_vars.push(note_hash);
        }

        // === Fee ===
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // === Balance equation ===
        // sum(inputs) = sum(outputs) + fee
        let sum_inputs = composer.arithmetic_gate(|gate| {
            gate.witness(input_amount_vars[0], input_amount_vars[1], None)
                .add(F::one(), F::one())
        });

        let sum_outputs = composer.arithmetic_gate(|gate| {
            gate.witness(output_amount_vars[0], output_amount_vars[1], None)
                .add(F::one(), F::one())
        });

        let sum_outputs_plus_fee = composer.arithmetic_gate(|gate| {
            gate.witness(sum_outputs, fee_var, None)
                .add(F::one(), F::one())
        });

        composer.assert_equal(sum_inputs, sum_outputs_plus_fee);

        // === Public inputs (order matches PlonkPublicInputsV1) ===
        // PI[0] = merkle_root
        let n = composer.circuit_bound();
        composer.constrain_to_constant(root_var, F::zero(), F::zero());
        pi_positions.push(n);

        // PI[1] = nullifier_0
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[0], F::zero(), F::zero());
        pi_positions.push(n);

        // PI[2] = nullifier_1
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[1], F::zero(), F::zero());
        pi_positions.push(n);

        // PI[3] = output_note_hash_0
        let n = composer.circuit_bound();
        composer.constrain_to_constant(output_note_hash_vars[0], F::zero(), F::zero());
        pi_positions.push(n);

        // PI[4] = output_note_hash_1
        let n = composer.circuit_bound();
        composer.constrain_to_constant(output_note_hash_vars[1], F::zero(), F::zero());
        pi_positions.push(n);

        // PI[5] = fee
        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), F::zero());
        pi_positions.push(n);

        self.pi_pos = pi_positions;

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 15 // 32768
    }
}