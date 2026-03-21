//! Shield Circuit (T→Z) — proves that an output commitment
//! matches a stated transparent amount.
//!
//! Public inputs (in order):
//!   PI[0] = transparent_amount (scaled by 10^18)
//!   PI[1] = output_note_hash  = Poseidon(amount, randomness)
//!
//! Private witnesses:
//!   - randomness (blinding factor for Pedersen commitment)
//!
//! Constraints:
//!   1. note_hash = Poseidon(transparent_amount, randomness)
//!   2. note_hash == PI[1]
//!   3. range_check(transparent_amount, 88 bits)

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::note_hash::note_hash_gadget;
use crate::gadgets::range::range_check;

/// Shield circuit witness data.
#[derive(Debug, Clone)]
pub struct ShieldCircuit<F: PrimeField> {
    /// The transparent amount being shielded (scaled × 10^18).
    pub amount_scaled: F,
    /// The blinding factor / randomness for the Pedersen commitment.
    pub randomness: F,
    /// Gate indices for public inputs (filled by gadget).
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for ShieldCircuit<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for ShieldCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_SHIELD_CIRCUIT_V1___________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        // Private witnesses
        let amount_var = composer.add_input(self.amount_scaled);
        let randomness_var = composer.add_input(self.randomness);

        // Compute note_hash = Poseidon(amount, randomness)
        let computed_note_hash = note_hash_gadget(composer, amount_var, randomness_var);

        // Range check on the amount (0 ≤ amount < 2^88)
        range_check(composer, amount_var);

        // Public inputs:
        //   PI[0] = transparent_amount
        //   PI[1] = output_note_hash
        // Use constrain_to_constant with value=0. During verification,
        // the actual public input value is added to the PI polynomial.
        let n = composer.circuit_bound();
        composer.constrain_to_constant(amount_var, F::zero(), F::zero());
        let pi0 = n;

        let n = composer.circuit_bound();
        composer.constrain_to_constant(computed_note_hash, F::zero(), F::zero());
        let pi1 = n;

        self.pi_pos = vec![pi0, pi1];

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        // Shield circuit is small. Poseidon ~300 constraints + range ~88 + overhead.
        // Round up to next power of 2 for FFT.
        1 << 12 // 4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ed_on_bls12_381::EdwardsParameters;
    use plonk_core::circuit::{verify_proof, Circuit};
    use plonk_core::commitment::KZG10;

    type PC = KZG10<Bls12_381>;

    #[test]
    fn shield_circuit_compiles() {
        let mut circuit = ShieldCircuit::<Fr> {
            amount_scaled: Fr::from(50_000_000_000_000_000_000u128),
            randomness: Fr::from(12345u64),
            pi_pos: Vec::new(),
        };

        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        circuit.gadget(&mut composer).expect("circuit should compile");
        assert!(composer.circuit_bound() > 0);
        assert_eq!(circuit.pi_pos.len(), 2);
    }

    #[test]
    fn shield_circuit_prove_verify_roundtrip() {
        use plonk_core::commitment::HomomorphicCommitment;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(42);
        let label = b"shield_test";

        // Setup universal params
        let pp = PC::setup(1 << 12, None, &mut rng).expect("setup failed");

        // 1. Compile circuit (with dummy witness for shape)
        let mut dummy = ShieldCircuit::<Fr>::default();
        let (pk, vd) = dummy
            .compile::<PC>(&pp)
            .expect("compile failed");

        // 2. Create real circuit with witness values
        let amount = Fr::from(50_000_000_000_000_000_000u128); // 50 VFX
        let randomness = Fr::from(9876543210u64);

        let mut circuit = ShieldCircuit::<Fr> {
            amount_scaled: amount,
            randomness,
            pi_pos: Vec::new(),
        };

        // 3. Generate proof
        let (proof, pi) = circuit
            .gen_proof::<PC>(&pp, pk, label)
            .expect("proof gen failed");

        // 4. Verify proof
        let verified = verify_proof::<Fr, EdwardsParameters, PC>(
            &pp,
            vd,
            &proof,
            &pi,
            label,
        );
        assert!(verified.is_ok(), "proof verification failed: {:?}", verified.err());
    }
}
