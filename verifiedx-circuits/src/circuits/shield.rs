//! Shield Circuit (T→Z) — proves that an output note matches a stated
//! transparent amount and names its owner.
//!
//! Public inputs (in order):
//!   PI[0] = transparent_amount (scaled by 10^8)
//!   PI[1] = output_note_hash  = Poseidon(amount, randomness, owner_pk)
//!
//! Private witnesses:
//!   - randomness (the note's blinding factor)
//!   - owner_pk   (the recipient's owner public key, from the recipient's zfx address)
//!
//! Constraints:
//!   1. note_hash = Poseidon(transparent_amount, randomness, owner_pk)
//!   2. note_hash == PI[1]
//!   3. range_check(transparent_amount, 88 bits)
//!
//! v2 (fund-loss re-audit, Oct 2026): the owner is part of the note, so only the holder of the matching
//! nullifier key can ever spend it; the sender, who knows amount and randomness, cannot.
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::error::Error;

use crate::gadgets::note_hash::note_hash_v2_gadget;
use crate::gadgets::range::range_check;

/// Shield circuit witness data.
#[derive(Debug, Clone)]
pub struct ShieldCircuit<F: PrimeField> {
    /// The transparent amount being shielded (scaled × 10^8).
    pub amount_scaled: F,
    /// The note's randomness.
    pub randomness: F,
    /// The recipient's owner public key (`Poseidon(OWNER_PK_DOMAIN, nullifier_key)`).
    pub owner_pk: F,
    /// Gate indices for public inputs (filled by gadget).
    pub pi_pos: Vec<usize>,
}

impl<F: PrimeField> Default for ShieldCircuit<F> {
    fn default() -> Self {
        Self {
            amount_scaled: F::zero(),
            randomness: F::zero(),
            owner_pk: F::zero(),
            pi_pos: Vec::new(),
        }
    }
}

impl<F, P> Circuit<F, P> for ShieldCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"VFX_SHIELD_CIRCUIT_V2___________";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        // Private witnesses
        let amount_var = composer.add_input(self.amount_scaled);
        let randomness_var = composer.add_input(self.randomness);
        let owner_var = composer.add_input(self.owner_pk);

        // note_hash = Poseidon(amount, randomness, owner_pk)
        let computed_note_hash = note_hash_v2_gadget(composer, amount_var, randomness_var, owner_var);

        // Range check on the amount (0 ≤ amount < 2^88)
        range_check(composer, amount_var);

        // Public inputs:
        //   PI[0] = transparent_amount
        //   PI[1] = output_note_hash
        let n = composer.circuit_bound();
        composer.constrain_to_constant(amount_var, F::zero(), Some(-self.amount_scaled));
        let pi0 = n;

        let note_hash_val = composer.value_of_var(computed_note_hash);
        let n = composer.circuit_bound();
        composer.constrain_to_constant(computed_note_hash, F::zero(), Some(-note_hash_val));
        let pi1 = n;

        self.pi_pos = vec![pi0, pi1];
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        // Three chained width-3 Poseidon permutations + the 88-bit range check + overhead.
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
            amount_scaled: Fr::from(5_000_000_000u64),
            randomness: Fr::from(12345u64),
            owner_pk: Fr::from(777u64),
            pi_pos: Vec::new(),
        };
        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        circuit.gadget(&mut composer).expect("circuit should compile");
        assert!(composer.circuit_bound() > 0);
        assert_eq!(circuit.pi_pos.len(), 2);
    }

    #[test]
    fn shield_circuit_prove_verify_roundtrip() {
        use ark_poly_commit::PolynomialCommitment;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(42);
        let label = b"shield_test";
        let pp = PC::setup(1 << 12, None, &mut rng).expect("setup failed");

        let mut dummy = ShieldCircuit::<Fr>::default();
        let (pk, (vk, _pi_pos)) =
            <ShieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::compile::<PC>(&mut dummy, &pp)
                .expect("compile failed");

        let mut circuit = ShieldCircuit::<Fr> {
            amount_scaled: Fr::from(5_000_000_000u64),
            randomness: Fr::from(9876543210u64),
            owner_pk: Fr::from(31337u64),
            pi_pos: Vec::new(),
        };
        let (proof, pi) =
            <ShieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::gen_proof::<PC>(&mut circuit, &pp, pk, label)
                .expect("proof gen failed");
        let verified = verify_proof::<Fr, EdwardsParameters, PC>(&pp, vk, &proof, &pi, label);
        assert!(verified.is_ok(), "proof verification failed: {:?}", verified.err());
    }
}
