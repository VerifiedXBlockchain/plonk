//! VFX Fee Circuit (1-in / 1-out), v2 — used by vBTC transfers to pay fees from shielded VFX.
//!
//! Public inputs (in order):
//!   PI[0] = vfx_merkle_root
//!   PI[1] = fee_nullifier
//!   PI[2] = change_note_hash
//!   PI[3] = fee_scaled
//!
//! v2 (fund-loss re-audit, Oct 2026): the input is an owner-bound note spent with its owner's nullifier key
//! and the change note names its owner (see `transfer.rs`).

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::merkle::TREE_DEPTH;
use crate::gadgets::range::range_check;

use super::transfer::{output_note_gadget, spend_input_gadget, TransferInput, TransferOutput};

/// Fee circuit witness data.
#[derive(Debug, Clone)]
pub struct FeeCircuit<F: PrimeField> {
    pub input_amount_scaled: F,
    pub input_randomness: F,
    /// The owner's nullifier key for the spent note.
    pub input_nullifier_key: F,
    pub input_position: F,
    pub input_merkle_path: [F; TREE_DEPTH],
    pub input_merkle_indices: [F; TREE_DEPTH],
    pub change_amount_scaled: F,
    pub change_randomness: F,
    /// The change note's owner.
    pub change_owner_pk: F,
    pub fee_scaled: F,
    pub merkle_root: F,
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for FeeCircuit<F> {
    fn default() -> Self {
        Self {
            input_amount_scaled: F::zero(),
            input_randomness: F::zero(),
            input_nullifier_key: F::zero(),
            input_position: F::zero(),
            input_merkle_path: [F::zero(); TREE_DEPTH],
            input_merkle_indices: [F::zero(); TREE_DEPTH],
            change_amount_scaled: F::zero(),
            change_randomness: F::zero(),
            change_owner_pk: F::zero(),
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
    const CIRCUIT_ID: [u8; 32] = *b"VFX_FEE_CIRCUIT_V2______________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(4);

        let root_var = composer.add_input(self.merkle_root);

        // Fee
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // Input
        let input = TransferInput {
            amount_scaled: self.input_amount_scaled,
            randomness: self.input_randomness,
            nullifier_key: self.input_nullifier_key,
            position: self.input_position,
            merkle_path: self.input_merkle_path,
            merkle_indices: self.input_merkle_indices,
        };
        let (in_amount_var, in_nullifier) = spend_input_gadget(composer, &input, root_var);

        // Change output
        let change = TransferOutput {
            amount_scaled: self.change_amount_scaled,
            randomness: self.change_randomness,
            owner_pk: self.change_owner_pk,
        };
        let (ch_amount_var, ch_note_hash) = output_note_gadget(composer, &change);

        // Balance: input = change + fee
        let change_plus_fee = composer.arithmetic_gate(|gate| {
            gate.witness(ch_amount_var, fee_var, None)
                .add(F::one(), F::one())
        });
        composer.assert_equal(in_amount_var, change_plus_fee);

        // Public inputs
        let n = composer.circuit_bound();
        composer.constrain_to_constant(root_var, F::zero(), Some(-self.merkle_root));
        pi_positions.push(n);

        let null_val = composer.value_of_var(in_nullifier);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(in_nullifier, F::zero(), Some(-null_val));
        pi_positions.push(n);

        let ch_hash_val = composer.value_of_var(ch_note_hash);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(ch_note_hash, F::zero(), Some(-ch_hash_val));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), Some(-self.fee_scaled));
        pi_positions.push(n);

        self.pi_pos = pi_positions;
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 14 // 16384
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ed_on_bls12_381::EdwardsParameters;

    #[test]
    fn fee_circuit_compiles_with_four_public_inputs() {
        let mut circuit = FeeCircuit::<Fr>::default();
        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        circuit.gadget(&mut composer).expect("gadget");
        assert_eq!(circuit.pi_pos.len(), 4);
        assert!(composer.circuit_bound() <= 1 << 14, "fee circuit exceeds its padded size: {}", composer.circuit_bound());
    }
}
