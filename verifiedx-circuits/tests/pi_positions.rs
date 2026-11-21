//! The public-input positions of the four circuits. The params file's verifier keys (which judge proofs under the
//! original rules) were made for circuits with exactly these gate positions; the circuits as built now must keep them,
//! or those keys would be handed public inputs at the wrong gates and refuse every proof mined before.

use verifiedx_circuits::circuit_keys::{pi_positions_fee, pi_positions_shield, pi_positions_transfer, pi_positions_unshield};

#[test]
fn the_public_input_positions_are_those_of_the_params_file_keys() {
    assert_eq!(pi_positions_shield(), vec![593, 594]);
    assert_eq!(pi_positions_transfer(), vec![16719, 16720, 16721, 16722, 16723, 16724]);
    assert_eq!(pi_positions_unshield(), vec![16143, 16144, 16145, 16146, 16147, 16148, 16149]);
    assert_eq!(pi_positions_fee(), vec![8368, 8369, 8370, 8371]);
}
