//! KZG universal parameters from the Zcash Sapling **Powers of Tau** ceremony (BLS12-381, 2017-2018, ~90 participants).
//!
//! The seeded `trusted_setup_v1` is NOT a trusted setup: its tau is derived from a constant, so anyone can recompute it
//! and forge a proof for any statement. Production params must come from a ceremony whose secret is gone. Zcash
//! publishes the prepared phase-1 outputs `phase1radix2m{k}` at `https://download.z.cash/downloads/powersoftau/`; this
//! module turns one into arkworks `UniversalParams` for the Sonic-style KZG10 `plonk-core` uses.
//!
//! File layout (`powersoftau` `prepare_phase2`, every point uncompressed in the Zcash encoding: big-endian with the
//! flag bits in the top three bits of the first byte; G1 = 96 bytes, G2 = 192 bytes):
//!
//! ```text
//! alpha_g1 (96) | beta_g1 (96) | beta_g2 (192)
//! coeffs_g1      : n x 96    Lagrange-basis points  L_j(tau)·G1 over the radix-2 domain of size n
//! coeffs_g2      : n x 192   L_j(tau)·G2
//! alpha_coeffs_g1: n x 96
//! beta_coeffs_g1 : n x 96
//! h              : (n-1) x 96
//! ```
//!
//! KZG needs the monomial powers tau^i·G1 (and G2, tau·G2). The Lagrange points are `ifft(tau^i·G)`, so one group FFT
//! over the same domain gives the monomial powers back exactly. The result is checked: tau^0·G1 and tau^0·G2 must be
//! the curve generators, and e(tau^i·G1, G2) == e(tau^(i-1)·G1, tau·G2) for a sample of i (a wrong domain generator or a
//! mis-read point fails these).
//!
//! Hiding is never used by the circuits (`trim(.., hiding_bound 0, ..)`), so `powers_of_gamma_g` is filled with the
//! plain powers (gamma = 1): it affects nothing the prover or verifier computes.

use std::collections::BTreeMap;

use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::UniversalParams;

const G1_LEN: usize = 96;
const G2_LEN: usize = 192;
const HEADER_LEN: usize = G1_LEN + G1_LEN + G2_LEN;

/// What the import produced, for the record the operator keeps next to the params file.
#[derive(Debug, Clone)]
pub struct ImportReport {
    pub domain_size: usize,
    pub powers_kept: usize,
    pub pairing_checks: usize,
}

fn fq_from_be(bytes: &[u8], what: &str) -> Result<Fq, String> {
    let f = Fq::from_be_bytes_mod_order(bytes);
    // Canonical: the bytes must be the element itself, not something that reduced into it.
    if f.into_repr().to_bytes_be() != bytes {
        return Err(format!("{what}: field element not canonical"));
    }
    Ok(f)
}

fn read_g1(bytes: &[u8]) -> Result<G1Affine, String> {
    if bytes.len() != G1_LEN {
        return Err("G1 point: wrong length".into());
    }
    let flags = bytes[0] & 0xE0;
    if flags & 0x80 != 0 {
        return Err("G1 point: compressed where uncompressed expected".into());
    }
    if flags & 0x40 != 0 {
        return Ok(G1Affine::zero());
    }
    let mut x = bytes[..48].to_vec();
    x[0] &= 0x1F;
    let x = fq_from_be(&x, "G1.x")?;
    let y = fq_from_be(&bytes[48..96], "G1.y")?;
    let p = G1Affine::new(x, y, false);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("G1 point: not on the curve / not in the subgroup".into());
    }
    Ok(p)
}

fn read_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    if bytes.len() != G2_LEN {
        return Err("G2 point: wrong length".into());
    }
    let flags = bytes[0] & 0xE0;
    if flags & 0x80 != 0 {
        return Err("G2 point: compressed where uncompressed expected".into());
    }
    if flags & 0x40 != 0 {
        return Ok(G2Affine::zero());
    }
    // Zcash order: x.c1, x.c0, y.c1, y.c0
    let mut xc1 = bytes[..48].to_vec();
    xc1[0] &= 0x1F;
    let x = Fq2::new(fq_from_be(&bytes[48..96], "G2.x.c0")?, fq_from_be(&xc1, "G2.x.c1")?);
    let y = Fq2::new(fq_from_be(&bytes[144..192], "G2.y.c0")?, fq_from_be(&bytes[96..144], "G2.y.c1")?);
    let p = G2Affine::new(x, y, false);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("G2 point: not on the curve / not in the subgroup".into());
    }
    Ok(p)
}

/// The domain size encoded by a `phase1radix2m{k}` file's length.
pub fn domain_size_of(file_len: usize) -> Result<usize, String> {
    // len = HEADER + n*96*3 + n*192 + (n-1)*96 = HEADER - 96 + n*576
    if file_len < HEADER_LEN || (file_len + 96 - HEADER_LEN) % 576 != 0 {
        return Err(format!("not a phase1radix file (length {file_len})"));
    }
    let n = (file_len + 96 - HEADER_LEN) / 576;
    if n == 0 || !n.is_power_of_two() {
        return Err(format!("phase1radix domain size {n} is not a power of two"));
    }
    Ok(n)
}

/// Monomial powers from the Lagrange points: `fft` over the domain of size `n` (the inverse of the ceremony's `ifft`).
fn monomial_g1(lagrange: &[G1Affine]) -> Result<Vec<G1Projective>, String> {
    let n = lagrange.len();
    let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or("no radix-2 domain of that size")?;
    let proj: Vec<G1Projective> = lagrange.iter().map(|p| p.into_projective()).collect();
    Ok(domain.fft(&proj))
}

fn monomial_g2(lagrange: &[G2Affine]) -> Result<Vec<G2Projective>, String> {
    let n = lagrange.len();
    let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or("no radix-2 domain of that size")?;
    let proj: Vec<G2Projective> = lagrange.iter().map(|p| p.into_projective()).collect();
    Ok(domain.fft(&proj))
}

/// Builds `UniversalParams` supporting polynomials up to `max_degree` from a `phase1radix2m{k}` file's bytes
/// (needs n > max_degree). Verifies the structure; refuses anything that does not check out.
pub fn universal_params_from_phase1radix(bytes: &[u8], max_degree: usize) -> Result<(UniversalParams<Bls12_381>, ImportReport), String> {
    let n = domain_size_of(bytes.len())?;
    if max_degree + 1 > n {
        return Err(format!("the file has {n} powers; {} are needed (max degree {max_degree})", max_degree + 1));
    }
    let mut off = HEADER_LEN; // alpha_g1, beta_g1, beta_g2 are Groth16's, not needed here
    let mut coeffs_g1 = Vec::with_capacity(n);
    for i in 0..n {
        coeffs_g1.push(read_g1(&bytes[off..off + G1_LEN]).map_err(|e| format!("coeffs_g1[{i}]: {e}"))?);
        off += G1_LEN;
    }
    // Only tau^0 and tau^1 of G2 are needed, but the FFT needs every Lagrange point.
    let mut coeffs_g2 = Vec::with_capacity(n);
    for i in 0..n {
        coeffs_g2.push(read_g2(&bytes[off..off + G2_LEN]).map_err(|e| format!("coeffs_g2[{i}]: {e}"))?);
        off += G2_LEN;
    }

    let g1_mono = monomial_g1(&coeffs_g1)?;
    let g2_mono = monomial_g2(&coeffs_g2)?;
    let powers_of_g = G1Projective::batch_normalization_into_affine(&g1_mono[..=max_degree]);
    let g2_first = G2Projective::batch_normalization_into_affine(&g2_mono[..2]);
    let h = g2_first[0];
    let beta_h = g2_first[1];

    // Structure checks.
    if powers_of_g[0] != G1Affine::prime_subgroup_generator() {
        return Err("tau^0·G1 is not the G1 generator: wrong domain or encoding".into());
    }
    if h != G2Affine::prime_subgroup_generator() {
        return Err("tau^0·G2 is not the G2 generator: wrong domain or encoding".into());
    }
    let mut checks = 0usize;
    let sample: Vec<usize> = (1..=4).chain([7usize, 64, 1023, 4096, max_degree / 2, max_degree].into_iter()).filter(|&i| i >= 1 && i <= max_degree).collect();
    for i in sample {
        let lhs = Bls12_381::pairing(powers_of_g[i], h);
        let rhs = Bls12_381::pairing(powers_of_g[i - 1], beta_h);
        if lhs != rhs {
            return Err(format!("pairing check failed at power {i}: e(tau^i G1, G2) != e(tau^(i-1) G1, tau G2)"));
        }
        checks += 1;
    }
    if powers_of_g.iter().any(|p| p.is_zero()) {
        return Err("a power of tau is the identity".into());
    }

    // Hiding is unused (hiding bound 0): gamma = 1 makes the gamma powers the plain powers. trim() reads 0..=1.
    let mut powers_of_gamma_g = BTreeMap::new();
    for i in 0..=2.min(max_degree) {
        powers_of_gamma_g.insert(i, powers_of_g[i]);
    }
    let pp = UniversalParams::<Bls12_381> {
        powers_of_g,
        powers_of_gamma_g,
        h,
        beta_h,
        neg_powers_of_h: BTreeMap::new(),
        prepared_h: h.into(),
        prepared_beta_h: beta_h.into(),
    };
    Ok((pp, ImportReport { domain_size: n, powers_kept: max_degree + 1, pairing_checks: checks }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_size_from_length() {
        assert_eq!(domain_size_of(18_874_656).unwrap(), 1 << 15);
        assert_eq!(domain_size_of(37_749_024).unwrap(), 1 << 16);
        assert!(domain_size_of(1000).is_err());
    }

    #[test]
    fn generator_round_trips_through_the_zcash_encoding() {
        // Encode the G1 generator the Zcash way and read it back.
        let g = G1Affine::prime_subgroup_generator();
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(&g.x.into_repr().to_bytes_be());
        bytes.extend_from_slice(&g.y.into_repr().to_bytes_be());
        assert_eq!(read_g1(&bytes).unwrap(), g);
        let g2 = G2Affine::prime_subgroup_generator();
        let mut b2 = Vec::with_capacity(192);
        b2.extend_from_slice(&g2.x.c1.into_repr().to_bytes_be());
        b2.extend_from_slice(&g2.x.c0.into_repr().to_bytes_be());
        b2.extend_from_slice(&g2.y.c1.into_repr().to_bytes_be());
        b2.extend_from_slice(&g2.y.c0.into_repr().to_bytes_be());
        assert_eq!(read_g2(&b2).unwrap(), g2);
        // Infinity flag and a compressed flag are handled / refused.
        let mut inf = vec![0u8; 96];
        inf[0] = 0x40;
        assert!(read_g1(&inf).unwrap().is_zero());
        let mut comp = bytes.clone();
        comp[0] |= 0x80;
        assert!(read_g1(&comp).is_err());
    }

    /// The real import: set ZCASH_PHASE1RADIX to a `phase1radix2m16` (or larger) file.
    #[test]
    fn imports_the_zcash_powers_of_tau() {
        let Ok(path) = std::env::var("ZCASH_PHASE1RADIX") else {
            eprintln!("zcash_setup: ZCASH_PHASE1RADIX not set; import test skipped");
            return;
        };
        let bytes = std::fs::read(&path).expect("read phase1radix");
        let (pp, report) = universal_params_from_phase1radix(&bytes, crate::circuit_keys::MAX_CIRCUIT_SIZE).expect("import");
        assert_eq!(pp.powers_of_g.len(), crate::circuit_keys::MAX_CIRCUIT_SIZE + 1);
        assert!(report.pairing_checks >= 6, "{report:?}");
        // The seeded setup and the ceremony's cannot share tau.
        let seeded = crate::trusted_setup_v1(false).expect("seeded setup");
        use ark_serialize::CanonicalDeserialize;
        let seeded_pp: UniversalParams<Bls12_381> = CanonicalDeserialize::deserialize(seeded.universal_params.as_slice()).unwrap();
        assert_ne!(seeded_pp.powers_of_g[1], pp.powers_of_g[1]);
    }
}
