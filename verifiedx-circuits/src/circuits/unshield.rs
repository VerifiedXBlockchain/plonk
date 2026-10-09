//! Unshield Circuit (Z→T), v2 — proves ownership of shielded inputs and outputs a transparent amount
//! to a bound recipient.
//!
//! Public inputs (in order):
//!   PI[0] = merkle_root
//!   PI[1] = nullifier_0
//!   PI[2] = nullifier_1
//!   PI[3] = transparent_amount (scaled)
//!   PI[4] = change_note_hash
//!   PI[5] = fee_scaled
//!   PI[6] = recipient_tag  (a field element the node derives from the transparent recipient address)
//!
//! v2 (fund-loss re-audit, Oct 2026): inputs are owner-bound notes spent with the owner's nullifier key (see
//! `transfer.rs`), and the recipient is a public input, so a finished unshield cannot be copied with another
//! `ToAddress` and still verify.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::range::range_check;

use super::transfer::{output_note_gadget, spend_input_gadget, TransferInput, TransferOutput};

/// Unshield circuit witness data.
#[derive(Debug, Clone)]
pub struct UnshieldCircuit<F: PrimeField> {
    pub inputs: [TransferInput<F>; 2],
    pub transparent_amount_scaled: F,
    pub change_amount_scaled: F,
    pub change_randomness: F,
    /// The change note's owner (normally the spender's own owner key).
    pub change_owner_pk: F,
    pub fee_scaled: F,
    pub merkle_root: F,
    /// The transparent recipient, as a field element (public input).
    pub recipient_tag: F,
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for UnshieldCircuit<F> {
    fn default() -> Self {
        Self {
            inputs: [TransferInput::default(), TransferInput::default()],
            transparent_amount_scaled: F::zero(),
            change_amount_scaled: F::zero(),
            change_randomness: F::zero(),
            change_owner_pk: F::zero(),
            fee_scaled: F::zero(),
            merkle_root: F::zero(),
            recipient_tag: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for UnshieldCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_UNSHIELD_CIRCUIT_V2_________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut pi_positions = Vec::with_capacity(7);

        let root_var = composer.add_input(self.merkle_root);

        // Fee
        let fee_var = composer.add_input(self.fee_scaled);
        range_check(composer, fee_var);

        // Transparent amount
        let transparent_var = composer.add_input(self.transparent_amount_scaled);
        range_check(composer, transparent_var);

        // Recipient (a public input the proof is bound to; its value carries no constraint of its own)
        let recipient_var = composer.add_input(self.recipient_tag);

        // Inputs
        let mut input_amount_vars = Vec::with_capacity(2);
        let mut nullifier_vars = Vec::with_capacity(2);
        for inp in &self.inputs {
            let (amount_var, nullifier) = spend_input_gadget(composer, inp, root_var);
            input_amount_vars.push(amount_var);
            nullifier_vars.push(nullifier);
        }

        // Change output
        let change = TransferOutput {
            amount_scaled: self.change_amount_scaled,
            randomness: self.change_randomness,
            owner_pk: self.change_owner_pk,
        };
        let (change_amount_var, change_note_hash) = output_note_gadget(composer, &change);

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
        composer.constrain_to_constant(root_var, F::zero(), Some(-self.merkle_root));
        pi_positions.push(n);

        let null0_val = composer.value_of_var(nullifier_vars[0]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[0], F::zero(), Some(-null0_val));
        pi_positions.push(n);

        let null1_val = composer.value_of_var(nullifier_vars[1]);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(nullifier_vars[1], F::zero(), Some(-null1_val));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(transparent_var, F::zero(), Some(-self.transparent_amount_scaled));
        pi_positions.push(n);

        let change_hash_val = composer.value_of_var(change_note_hash);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(change_note_hash, F::zero(), Some(-change_hash_val));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(fee_var, F::zero(), Some(-self.fee_scaled));
        pi_positions.push(n);

        let n = composer.circuit_bound();
        composer.constrain_to_constant(recipient_var, F::zero(), Some(-self.recipient_tag));
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
    fn unshield_circuit_compiles_with_seven_public_inputs() {
        let mut circuit = UnshieldCircuit::<Fr>::default();
        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        circuit.gadget(&mut composer).expect("gadget");
        assert_eq!(circuit.pi_pos.len(), 7);
        assert!(composer.circuit_bound() <= 1 << 15, "unshield circuit exceeds its padded size: {}", composer.circuit_bound());
    }
}
