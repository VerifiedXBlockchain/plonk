//! Nullifier derivation gadget.
//!
//! `nullifier = Poseidon(nullifier_key, note_hash, position)`
//!
//! v2 (fund-loss re-audit, Oct 2026): the first input is the owner's nullifier key, and the circuits also
//! prove `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)` is the owner key inside `note_hash`, so a
//! nullifier can only be produced by the note's owner and is unique per note. (In v1 the key was a free
//! witness: anyone knowing the note could spend it once per key.)

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;

use super::poseidon::poseidon_hash_3;

/// Derive a nullifier in-circuit.
///
/// `nullifier = Poseidon(viewing_key, note_hash, position)`
///
/// Returns the nullifier variable, which should be constrained
/// equal to the corresponding public input.
pub fn nullifier_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    viewing_key: Variable,
    note_hash: Variable,
    position: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    poseidon_hash_3(composer, viewing_key, note_hash, position)
}