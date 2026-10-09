//! Note hash gadgets.
//!
//! v1: `note_hash = Poseidon(amount, randomness)` — the note names no owner, so anyone who learns
//! `(amount, randomness, position)` (the sender always does) can spend it with any nullifier key, once per
//! key. Kept only for the legacy helpers; no v2 circuit uses it.
//!
//! v2 (fund-loss re-audit, Oct 2026): `note_hash = Poseidon(amount, randomness, owner_pk)` with
//! `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)`. A spend proves knowledge of the `nullifier_key`
//! behind the note's `owner_pk`, so only the owner can spend, and `nullifier = Poseidon(nullifier_key,
//! note_hash, position)` is unique per note. A recipient is bound into every output through its `owner_pk`.
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;

use super::poseidon::{poseidon_hash_2, poseidon_hash_3};

/// Domain separator of the owner public key: `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)`.
/// ASCII `VFX_OWNR` as a little-endian u64; Core computes the same value (`PoseidonV1.OwnerPk`).
pub const OWNER_PK_DOMAIN: u64 = 0x524E_574F_5F58_4656; // b"VFX_OWNR" read little-endian

/// Compute `note_hash = Poseidon(amount_scaled, randomness_fr)` in-circuit (v1 shape; legacy only).
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

/// Compute `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)` in-circuit. The domain is a constant gate,
/// so a prover cannot pick it.
pub fn owner_pk_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    nullifier_key: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let domain = composer.add_input(F::from(OWNER_PK_DOMAIN));
    composer.constrain_to_constant(domain, F::from(OWNER_PK_DOMAIN), None);
    poseidon_hash_2(composer, domain, nullifier_key)
}

/// Compute `note_hash = Poseidon(amount_scaled, randomness, owner_pk)` in-circuit (v2: the owner is in the note).
pub fn note_hash_v2_gadget<F, P>(
    composer: &mut StandardComposer<F, P>,
    amount_scaled: Variable,
    randomness: Variable,
    owner_pk: Variable,
) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    poseidon_hash_3(composer, amount_scaled, randomness, owner_pk)
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
    poseidon_hash_3(composer, amount_scaled, randomness, asset_id)
}
