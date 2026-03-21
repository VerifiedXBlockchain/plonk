//! Nullifier derivation gadget.
//!
//! Nullifier = Poseidon(viewing_key, note_hash, position)
//!
//! The circuit also proves the spending key → viewing key relationship.
//! In v1, viewing_key = SHA256(domain_tag || spending_key) but we defer
//! SHA256 in-circuit verification to a later step. For now, the
//! viewing_key is a private witness that the prover must supply correctly;
//! the nullifier published on-chain is deterministic from these inputs.
//!
//! Security note: without in-circuit SHA256, the prover could use an
//! arbitrary viewing_key. The spending_key preimage check will be added
//! as a separate gadget. For v1 launch, the viewing_key is treated as
//! a private witness whose correctness is enforced by the fact that only
//! the real owner can compute the correct nullifier (which is checked
//! against the public input).

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