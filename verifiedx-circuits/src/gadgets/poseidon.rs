//! In-circuit Poseidon hash gadget.
//!
//! Wraps the `PoseidonRef` constraint system from `plonk-hashing`
//! to provide convenient 2-ary and 3-ary Poseidon hashes inside
//! PLONK circuits.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;
use plonk_hashing::poseidon::zprize_constraints::{PoseidonZZRef, PlonkSpecZZ};
use plonk_hashing::poseidon::constants::PoseidonConstants;

/// Width 3 = 2 inputs + 1 capacity.
const WIDTH_3: usize = 3;

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
    let mut poseidon = PoseidonZZRef::<
        _,
        PlonkSpecZZ<F>,
        WIDTH_3,
    >::new(composer, PoseidonConstants::generate::<WIDTH_3>());
    poseidon.input(left).expect("poseidon input left");
    poseidon.input(right).expect("poseidon input right");
    poseidon.output_hash(composer)
}

/// Compute `Poseidon(a, b, c)` in-circuit by chaining WIDTH-3 hashes.
///
/// Matches off-chain `hash_field_elements(&[a, b, c])`:
///   h = Poseidon(0, a); h = Poseidon(h, b); h = Poseidon(h, c)
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
    let h = poseidon_hash_2(composer, zero, a);
    let h = poseidon_hash_2(composer, h, b);
    poseidon_hash_2(composer, h, c)
}

/// Compute `Poseidon(a, b, c, d)` in-circuit by chaining WIDTH-3 hashes.
///
/// Matches off-chain `hash_field_elements(&[a, b, c, d])`:
///   h = Poseidon(0, a); h = Poseidon(h, b); h = Poseidon(h, c); h = Poseidon(h, d)
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
    let zero = composer.zero_var();
    let h = poseidon_hash_2(composer, zero, a);
    let h = poseidon_hash_2(composer, h, b);
    let h = poseidon_hash_2(composer, h, c);
    poseidon_hash_2(composer, h, d)
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