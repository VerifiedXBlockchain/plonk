//! Note hash gadget — Poseidon(amount, randomness).
//!
//! The note hash serves as the Merkle leaf and binds the amount
//! to the commitment in-circuit, preventing inflation attacks.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;

use super::poseidon::poseidon_hash_2;

/// Compute `note_hash = Poseidon(amount_scaled, randomness_fr)` in-circuit.
///
/// Both inputs are field elements (the amount is pre-scaled by 10^18).
/// Returns the note_hash variable.
pub fn note_hash_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    amount_scaled: Variable,
    randomness: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    poseidon_hash_2(composer, amount_scaled, randomness)
}

/// Compute `note_hash_with_asset = Poseidon(amount_scaled, randomness, asset_id)`
/// in-circuit. Used for vBTC commitments where the asset (contract UID hash)
/// must be bound into the note.
pub fn note_hash_with_asset_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    amount_scaled: Variable,
    randomness: Variable,
    asset_id: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    super::poseidon::poseidon_hash_3(composer, amount_scaled, randomness, asset_id)
}