use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Second Pedersen generator: deterministic RNG-derived point.
static H_POINT: Lazy<G1Affine> = Lazy::new(|| {
    let mut rng = StdRng::seed_from_u64(0x5646_5850_5244_5658);
    G1Projective::rand(&mut rng).into_affine()
});

pub fn commit(amount_scaled: u64, randomness: &[u8]) -> Result<[u8; 48], ()> {
    if randomness.len() != 32 {
        return Err(());
    }
    let g = G1Affine::prime_subgroup_generator().into_projective();
    let h = G1Projective::from(*H_POINT);
    let a = Fr::from(amount_scaled);
    let r = Fr::from_le_bytes_mod_order(randomness);
    let c = g.mul(a.into_repr()) + h.mul(r.into_repr());
    let aff = c.into_affine();
    let mut out = [0u8; 48];
    aff.serialize(&mut out[..]).map_err(|_| ())?;
    Ok(out)
}

pub fn verify(commitment: &[u8], amount_scaled: u64, randomness: &[u8]) -> Result<bool, ()> {
    if commitment.len() != 48 || randomness.len() != 32 {
        return Err(());
    }
    let expected = commit(amount_scaled, randomness)?;
    Ok(expected == commitment)
}
