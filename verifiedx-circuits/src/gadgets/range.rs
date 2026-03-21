//! Range proof gadget — 88-bit range check.
//!
//! Proves `0 ≤ amount < 2^88` using the composer's built-in
//! range gate (bit decomposition).

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::StandardComposer;
use plonk_core::constraint_system::Variable;

/// Number of bits for the range proof. 2^88 ≈ 3.09 × 10^26,
/// which covers the max VFX supply of 2 × 10^26 (200M × 10^18).
pub const RANGE_BITS: usize = 88;

/// Constrain `amount` to be in range `[0, 2^88)`.
pub fn range_check<F, P>(
    composer: &mut StandardComposer<F, P>,
    amount: Variable,
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.range_gate(amount, RANGE_BITS);
}