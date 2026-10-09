//! Transfer Circuit (2-in / 2-out, Z→Z), v2.
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
//!     1. owner_pk_i  = Poseidon(OWNER_PK_DOMAIN, nullifier_key_i)
//!     2. note_hash_i = Poseidon(amount_i, randomness_i, owner_pk_i)
//!     3. nullifier_i = Poseidon(nullifier_key_i, note_hash_i, position_i)
//!     4. nullifier_i == PI nullifier_i
//!     5. Merkle path from note_hash_i to root is valid
//!     6. range_check(amount_i)
//!   For each output j:
//!     7. out_note_hash_j = Poseidon(out_amount_j, out_randomness_j, out_owner_pk_j)
//!     8. out_note_hash_j == PI output_note_hash_j
//!     9. range_check(out_amount_j)
//!   Balance:
//!    10. sum(input_amounts) = sum(output_amounts) + fee
//!
//! v2 (fund-loss re-audit, Oct 2026): a note names its owner, a spend proves knowledge of the owner's nullifier
//! key, so (a) only the owner can spend a note and (b) the nullifier of a note is unique. Every output binds its
//! recipient through the owner key in its note hash.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::merkle::{merkle_path_verify, TREE_DEPTH};
use crate::gadgets::note_hash::{note_hash_v2_gadget, owner_pk_gadget};
use crate::gadgets::nullifier::nullifier_gadget;
use crate::gadgets::range::range_check;

/// Per-input witness data for the transfer circuit.
#[derive(Debug, Clone)]
pub struct TransferInput<F: PrimeField> {
    pub amount_scaled: F,
    pub randomness: F,
    /// The owner's nullifier key: `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)` must be the key in the note.
    pub nullifier_key: F,
    pub position: F,
    pub merkle_path: [F; TREE_DEPTH],
    pub merkle_indices: [F; TREE_DEPTH],
}

impl<F: PrimeField> Default for TransferInput<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
            nullifier_key: F::zero(),
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
    /// The recipient's owner public key.
    pub owner_pk: F,
}

impl<F: PrimeField> Default for TransferOutput<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
            owner_pk: F::zero(),
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

/// Adds one spent note to the composer: owner key, note hash, nullifier, Merkle membership and range check.
/// Returns `(amount_var, nullifier_var)`. Shared by the Transfer, Unshield and Fee circuits.
pub(crate) fn spend_input_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    inp: &TransferInput<F>,
    root_var: plonk_core::constraint_system::Variable,
) -> (plonk_core::constraint_system::Variable, plonk_core::constraint_system::Variable)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let amount_var = composer.add_input(inp.amount_scaled);
    let randomness_var = composer.add_input(inp.randomness);
    let nk_var = composer.add_input(inp.nullifier_key);
    let pos_var = composer.add_input(inp.position);

    let mut path_vars = [composer.zero_var(); TREE_DEPTH];
    let mut idx_vars = [composer.zero_var(); TREE_DEPTH];
    for j in 0..TREE_DEPTH {
        path_vars[j] = composer.add_input(inp.merkle_path[j]);
        idx_vars[j] = composer.add_input(inp.merkle_indices[j]);
    }

    // owner_pk = Poseidon(DOMAIN, nk); note_hash = Poseidon(amount, randomness, owner_pk)
    let owner_pk = owner_pk_gadget(composer, nk_var);
    let note_hash = note_hash_v2_gadget(composer, amount_var, randomness_var, owner_pk);
    // nullifier = Poseidon(nk, note_hash, position)
    let nullifier = nullifier_gadget(composer, nk_var, note_hash, pos_var);
    // Merkle membership against the shared root
    merkle_path_verify(composer, note_hash, &path_vars, &idx_vars, root_var);
    range_check(composer, amount_var);
    (amount_var, nullifier)
}

/// Adds one output note to the composer. Returns `(amount_var, note_hash_var)`.
pub(crate) fn output_note_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    out: &TransferOutput<F>,
) -> (plonk_core::constraint_system::Variable, plonk_core::constraint_system::Variable)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let amount_var = composer.add_input(out.amount_scaled);
    let randomness_var = composer.add_input(out.randomness);
    let owner_var = composer.add_input(out.owner_pk);
    let note_hash = note_hash_v2_gadget(composer, amount_var, randomness_var, owner_var);
    range_check(composer, amount_var);
    (amount_var, note_hash)
}

impl<F, P> Circuit<F, P> for TransferCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_TRANSFER_CIRCUIT_V2_________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(6);

        // Merkle root as a witness variable (constrained as PI below)
        let root_var = composer.add_input(self.merkle_root);

        // === Inputs ===
        let mut input_amount_vars = Vec::with_capacity(2);
        let mut nullifier_vars = Vec::with_capacity(2);
        for inp in &self.inputs {
            let (amount_var, nullifier) = spend_input_gadget(composer, inp, root_var);
            input_amount_vars.push(amount_var);
            nullifier_vars.push(nullifier);
        }

        // === Outputs ===
        let mut output_amount_vars = Vec::with_capacity(2);
        let mut output_note_hash_vars = Vec::with_capacity(2);
        for out in &self.outputs {
            let (amount_var, note_hash) = output_note_gadget(composer, out);
            output_amount_vars.push(amount_var);
            output_note_hash_vars.push(note_hash);
        }

        // === Fee ===
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // === Balance: sum(inputs) = sum(outputs) + fee ===
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

        // === Public inputs (order matches the VFXPI1 version-3 layout) ===
        // PI[0] = merkle_root
        let n = composer.circuit_bound();
        composer.constrain_to_constant(root_var, F::zero(), Some(-self.merkle_root));
        pi_positions.push(n);
        // PI[1] = nullifier_0
        let null0_val = composer.value_of_var(nullifier_vars[0]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[0], F::zero(), Some(-null0_val));
        pi_positions.push(n);
        // PI[2] = nullifier_1
        let null1_val = composer.value_of_var(nullifier_vars[1]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[1], F::zero(), Some(-null1_val));
        pi_positions.push(n);
        // PI[3] = output_note_hash_0
        let out_hash0_val = composer.value_of_var(output_note_hash_vars[0]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(output_note_hash_vars[0], F::zero(), Some(-out_hash0_val));
        pi_positions.push(n);
        // PI[4] = output_note_hash_1
        let out_hash1_val = composer.value_of_var(output_note_hash_vars[1]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(output_note_hash_vars[1], F::zero(), Some(-out_hash1_val));
        pi_positions.push(n);
        // PI[5] = fee
        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), Some(-self.fee_scaled));
        pi_positions.push(n);

        self.pi_pos = pi_positions;
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 15 // 32768
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ed_on_bls12_381::EdwardsParameters;

    #[test]
    fn transfer_circuit_compiles_with_six_public_inputs() {
        let mut circuit = TransferCircuit::<Fr>::default();
        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        circuit.gadget(&mut composer).expect("gadget");
        assert_eq!(circuit.pi_pos.len(), 6);
        assert!(composer.circuit_bound() <= 1 << 15, "transfer circuit exceeds its padded size: {}", composer.circuit_bound());
    }
}
