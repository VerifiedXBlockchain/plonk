//! In-circuit Poseidon hash gadget.
//!
//! Wraps the `PoseidonRef` constraint system from `plonk-hashing`
//! to provide convenient 2-ary and 3-ary Poseidon hashes inside
//! PLONK circuits.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;
use plonk_hashing::poseidon::zprize_constraints::PoseidonRef;

/// Width 3 = 2 inputs + 1 capacity (suitable for binary Merkle tree).
const WIDTH_3: usize = 3;
/// Width 5 = 4 inputs + 1 capacity (for ternary/4-ary hash).
const WIDTH_5: usize = 5;

/// Compute `Poseidon(left, right)` in-circuit (width-3, 2 inputs).
///
/// Returns the output variable constrained to equal the Poseidon hash.
pub fn poseidon_hash_2<F, P>(
    composer: &mut StandardComposer<F, P>,
    left: Variable,
    right: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let mut poseidon = PoseidonRef::<
        _,
        plonk_hashing::poseidon::zprize_constraints::PlonkSpec<WIDTH_3>,
        WIDTH_3,
    >::new(composer);
    poseidon.input(left).expect("poseidon input left");
    poseidon.input(right).expect("poseidon input right");
    poseidon.output_hash(composer)
}

/// Compute `Poseidon(a, b, c)` in-circuit (width-5, 3 of 4 slots, last zero-padded).
///
/// Returns the output variable constrained to equal the Poseidon hash.
pub fn poseidon_hash_3<F, P>(
    composer: &mut StandardComposer<F, P>,
    a: Variable,
    b: Variable,
    c: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let zero = composer.zero_var();
    let mut poseidon = PoseidonRef::<
        _,
        plonk_hashing::poseidon::zprize_constraints::PlonkSpec<WIDTH_5>,
        WIDTH_5,
    >::new(composer);
    poseidon.input(a).expect("poseidon input a");
    poseidon.input(b).expect("poseidon input b");
    poseidon.input(c).expect("poseidon input c");
    poseidon.input(zero).expect("poseidon input pad");
    poseidon.output_hash(composer)
}

/// Compute `Poseidon(a, b, c, d)` in-circuit (width-5, 4 inputs).
///
/// Returns the output variable constrained to equal the Poseidon hash.
pub fn poseidon_hash_4<F, P>(
    composer: &mut StandardComposer<F, P>,
    a: Variable,
    b: Variable,
    c: Variable,
    d: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let mut poseidon = PoseidonRef::<
        _,
        plonk_hashing::poseidon::zprize_constraints::PlonkSpec<WIDTH_5>,
        WIDTH_5,
    >::new(composer);
    poseidon.input(a).expect("poseidon input a");
    poseidon.input(b).expect("poseidon input b");
    poseidon.input(c).expect("poseidon input c");
    poseidon.input(d).expect("poseidon input d");
    poseidon.output_hash(composer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ed_on_bls12_381::EdwardsParameters;

    #[test]
    fn poseidon_hash_2_deterministic() {
        let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
        let a = composer.add_input(Fr::from(42u64));
        let b = composer.add_input(Fr::from(99u64));
        let _h1 = poseidon_hash_2(&mut composer, a, b);

        let a2 = composer.add_input(Fr::from(42u64));
        let b2 = composer.add_input(Fr::from(99u64));
        let _h2 = poseidon_hash_2(&mut composer, a2, b2);

        assert!(composer.circuit_bound() > 0);
    }
}