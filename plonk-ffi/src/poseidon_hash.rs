//! Variable-length hash using plonk-hashing Poseidon (WIDTH = 3) in a chain:
//! `h := 0; for e in elems { h := Poseidon(h, e) }` with the same constants as PLONK circuits.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use once_cell::sync::Lazy;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use plonk_hashing::poseidon::poseidon_ref::{NativeSpecRef, PoseidonRef};

static POSEIDON_W3: Lazy<PoseidonConstants<Fr>> =
    Lazy::new(|| PoseidonConstants::generate::<3>());

fn compress2(prev: Fr, elem: Fr) -> Fr {
    let mut com = ();
    let mut p = PoseidonRef::<_, NativeSpecRef<Fr>, 3>::new(&mut com, POSEIDON_W3.clone());
    p.input(prev).expect("poseidon state");
    p.input(elem).expect("poseidon state");
    p.output_hash(&mut com)
}

fn fr_to_le_32(fr: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = fr.into_repr().to_bytes_le();
    let n = b.len().min(32);
    out[..n].copy_from_slice(&b[..n]);
    out
}

pub fn hash_field_elements(elements: &[Fr]) -> Result<[u8; 32], ()> {
    let mut h = Fr::from(0u64);
    if elements.is_empty() {
        h = compress2(Fr::from(0u64), Fr::from(0u64));
    } else {
        for e in elements {
            h = compress2(h, *e);
        }
    }
    Ok(fr_to_le_32(h))
}

/// Interpret `data` as a sequence of 32-byte big-endian field elements; pad last chunk with zeros.
pub fn hash_bytes(data: &[u8]) -> Result<[u8; 32], ()> {
    if data.is_empty() {
        return hash_field_elements(&[Fr::from(0u64)]);
    }
    let mut elems = Vec::new();
    for chunk in data.chunks(32) {
        let mut buf = [0u8; 32];
        buf[..chunk.len()].copy_from_slice(chunk);
        elems.push(Fr::from_be_bytes_mod_order(&buf));
    }
    hash_field_elements(&elems)
}

pub fn nullifier_from_parts(
    viewing_key: &[u8],
    commitment: &[u8],
    tree_position: u64,
) -> Result<[u8; 32], ()> {
    if viewing_key.len() != 32 {
        return Err(());
    }
    let mut vk = [0u8; 32];
    vk.copy_from_slice(viewing_key);
    let vk_fr = Fr::from_le_bytes_mod_order(&vk);
    let comm_digest = hash_bytes(commitment)?;
    let comm_fr = Fr::from_be_bytes_mod_order(&comm_digest);
    let pos_fr = Fr::from(tree_position);
    hash_field_elements(&[vk_fr, comm_fr, pos_fr])
}
