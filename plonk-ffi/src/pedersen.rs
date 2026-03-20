use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

/// Homomorphic addition of Pedersen commitments (G1 group add on compressed encodings).
pub fn commitment_add(a: &[u8], b: &[u8]) -> Result<[u8; 48], ()> {
    if a.len() != 48 || b.len() != 48 {
        return Err(());
    }
    let pa = G1Affine::deserialize(&mut &a[..]).map_err(|_| ())?;
    let pb = G1Affine::deserialize(&mut &b[..]).map_err(|_| ())?;
    let sum = (G1Projective::from(pa) + G1Projective::from(pb)).into_affine();
    let mut out = [0u8; 48];
    sum.serialize(&mut out[..]).map_err(|_| ())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;

    #[test]
    fn pedersen_homomorphic_add() {
        let r1 = [3u8; 32];
        let r2 = [5u8; 32];
        let c1 = commit(100, &r1).unwrap();
        let c2 = commit(50, &r2).unwrap();
        let c_add = commitment_add(&c1, &c2).unwrap();
        let sum_fr = Fr::from_le_bytes_mod_order(&r1) + Fr::from_le_bytes_mod_order(&r2);
        let mut r_sum = [0u8; 32];
        let b = sum_fr.into_repr().to_bytes_le();
        let n = b.len().min(32);
        r_sum[..n].copy_from_slice(&b[..n]);
        let expected = commit(150, &r_sum).unwrap();
        assert_eq!(c_add, expected);
    }
}
