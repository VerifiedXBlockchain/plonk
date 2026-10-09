//! VerifiedX `PlonkPublicInputsV1` wire format (must match `VerifiedXCore/Privacy/PlonkPublicInputsV1.cs`).
//!
//! Version 1 (the original layout, carrying Pedersen G1 commitments) is what the v0 digest-binding circuit
//! verified. The v1 real circuits bind *note hashes*, not G1 commitments, so **version 2** of the blob carries
//! the values the circuits expose as public inputs, in the circuits' public-input order:
//!
//! | circuit  | after header(8) + asset_tag(32) + merkle_root(32)                                   | total |
//! |----------|---------------------------------------------------------------------------------------|-------|
//! | Shield   | amount u64 LE (8), note_hash (32)                                                    | 112   |
//! | Unshield | fee u64 (8), transparent u64 (8), null0 (32), null1 (32), change_note_hash (32)      | 184   |
//! | Transfer | fee u64 (8), null0 (32), null1 (32), out_note_hash0 (32), out_note_hash1 (32)        | 208   |
//! | Fee      | fee u64 (8), nullifier (32), change_note_hash (32)                                   | 144   |
//!
//! Field elements are 32 little-endian bytes in arkworks canonical form. The asset tag is bound by the
//! transaction hash on chain, not by the circuits (the circuits know nothing of it).

use ark_bls12_381::Fr;

pub const MAGIC: &[u8] = b"VFXPI1";
pub const VERSION: u8 = 1;
pub const VERSION_2: u8 = 2;
/// Header: magic (6) + version (1) + circuit (1) = 8 bytes.
pub const HEADER_LEN: usize = 8;
const ASSET_OFF: usize = HEADER_LEN;
const ROOT_OFF: usize = ASSET_OFF + 32;
const BODY_OFF: usize = ROOT_OFF + 32;

/// Circuit byte (matches `PlonkCircuitType` in C#).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    Transfer = 0,
    Shield = 1,
    Unshield = 2,
    Fee = 3,
}

impl Circuit {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Circuit::Transfer),
            1 => Some(Circuit::Shield),
            2 => Some(Circuit::Unshield),
            3 => Some(Circuit::Fee),
            _ => None,
        }
    }

    /// Total `public_inputs` length for this circuit (version 1).
    pub fn total_len(self) -> usize {
        match self {
            Circuit::Transfer => 240,
            Circuit::Shield => 128,
            Circuit::Unshield => 200,
            Circuit::Fee => 160,
        }
    }

    /// Total `public_inputs` length for this circuit (version 2).
    pub fn total_len_v2(self) -> usize {
        match self {
            Circuit::Shield => BODY_OFF + 8 + 32,
            Circuit::Unshield => BODY_OFF + 8 + 8 + 32 + 32 + 32,
            Circuit::Transfer => BODY_OFF + 8 + 32 + 32 + 32 + 32,
            Circuit::Fee => BODY_OFF + 8 + 32 + 32,
        }
    }

    /// Number of public inputs the v1 circuit exposes.
    pub fn public_input_count(self) -> usize {
        match self {
            Circuit::Shield => 2,
            Circuit::Unshield => 6,
            Circuit::Transfer => 6,
            Circuit::Fee => 4,
        }
    }
}

/// Whether `data` starts with the VFXPI1 magic (any version).
pub fn is_vfxpi(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && &data[0..MAGIC.len()] == MAGIC
}

/// The version byte of a VFXPI1 blob, or None.
pub fn version(data: &[u8]) -> Option<u8> {
    if is_vfxpi(data) { Some(data[MAGIC.len()]) } else { None }
}

/// Parsed header + validated full length (version 1).
pub fn parse_public_inputs(data: &[u8]) -> Result<Circuit, ()> {
    if data.len() < HEADER_LEN {
        return Err(());
    }
    if &data[0..MAGIC.len()] != MAGIC {
        return Err(());
    }
    if data[MAGIC.len()] != VERSION {
        return Err(());
    }
    let circuit_byte = data[MAGIC.len() + 1];
    let c = Circuit::from_byte(circuit_byte).ok_or(())?;
    if data.len() != c.total_len() {
        return Err(());
    }
    Ok(c)
}

/// A version-2 blob, decoded into the circuit's public inputs in circuit order (un-negated values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputsV2 {
    pub circuit: Circuit,
    pub asset_tag: [u8; 32],
    pub merkle_root: Fr,
    /// The circuit's public inputs, in the order the circuit constrains them.
    pub values: Vec<Fr>,
}

fn fr_at(data: &[u8], off: usize) -> Result<Fr, ()> {
    crate::poseidon_v1::fr_from_le_canonical(&data[off..off + 32])
}

fn u64_at(data: &[u8], off: usize) -> Fr {
    Fr::from(u64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes")))
}

/// Parses a version-2 blob. Err when the magic, version, circuit byte, length or a field element is wrong.
pub fn parse_public_inputs_v2(data: &[u8]) -> Result<PublicInputsV2, ()> {
    if !is_vfxpi(data) || data[MAGIC.len()] != VERSION_2 {
        return Err(());
    }
    let circuit = Circuit::from_byte(data[MAGIC.len() + 1]).ok_or(())?;
    if data.len() != circuit.total_len_v2() {
        return Err(());
    }
    let mut asset_tag = [0u8; 32];
    asset_tag.copy_from_slice(&data[ASSET_OFF..ASSET_OFF + 32]);
    let merkle_root = fr_at(data, ROOT_OFF)?;
    let b = BODY_OFF;
    let values = match circuit {
        Circuit::Shield => vec![u64_at(data, b), fr_at(data, b + 8)?],
        Circuit::Unshield => vec![
            merkle_root,
            fr_at(data, b + 16)?,
            fr_at(data, b + 48)?,
            u64_at(data, b + 8),
            fr_at(data, b + 80)?,
            u64_at(data, b),
        ],
        Circuit::Transfer => vec![
            merkle_root,
            fr_at(data, b + 8)?,
            fr_at(data, b + 40)?,
            fr_at(data, b + 72)?,
            fr_at(data, b + 104)?,
            u64_at(data, b),
        ],
        Circuit::Fee => vec![merkle_root, fr_at(data, b + 8)?, fr_at(data, b + 40)?, u64_at(data, b)],
    };
    Ok(PublicInputsV2 { circuit, asset_tag, merkle_root, values })
}

/// Builds a version-2 blob from the on-chain fields (the inverse of `parse_public_inputs_v2`; used by tests
/// and available to any Rust caller that wants the canonical encoding).
pub struct V2Fields<'a> {
    pub asset_tag: [u8; 32],
    pub merkle_root: Fr,
    /// Shield: amount. Unshield / Transfer / Fee: fee.
    pub amount_or_fee: u64,
    /// Unshield only: the transparent amount.
    pub transparent: u64,
    /// Shield: [note_hash]. Unshield: [null0, null1, change_hash]. Transfer: [null0, null1, out0, out1]. Fee: [null, change_hash].
    pub elements: &'a [Fr],
}

pub fn encode_public_inputs_v2(circuit: Circuit, f: &V2Fields) -> Result<Vec<u8>, ()> {
    let expected_elems = match circuit {
        Circuit::Shield => 1,
        Circuit::Unshield => 3,
        Circuit::Transfer => 4,
        Circuit::Fee => 2,
    };
    if f.elements.len() != expected_elems {
        return Err(());
    }
    let mut out = Vec::with_capacity(circuit.total_len_v2());
    out.extend_from_slice(MAGIC);
    out.push(VERSION_2);
    out.push(circuit as u8);
    out.extend_from_slice(&f.asset_tag);
    out.extend_from_slice(&crate::poseidon_v1::fr_to_le(&f.merkle_root));
    out.extend_from_slice(&f.amount_or_fee.to_le_bytes());
    if circuit == Circuit::Unshield {
        out.extend_from_slice(&f.transparent.to_le_bytes());
    }
    for e in f.elements {
        out.extend_from_slice(&crate::poseidon_v1::fr_to_le(e));
    }
    debug_assert_eq!(out.len(), circuit.total_len_v2());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_csharp_layout() {
        assert_eq!(Circuit::Transfer.total_len(), 8 + 32 + 32 + 8 + 64 + 96);
        assert_eq!(Circuit::Shield.total_len(), 8 + 32 + 32 + 8 + 48);
        assert_eq!(Circuit::Unshield.total_len(), 8 + 32 + 32 + 8 + 8 + 64 + 48);
        assert_eq!(Circuit::Fee.total_len(), 8 + 32 + 32 + 8 + 32 + 48);
    }

    #[test]
    fn v2_lengths() {
        assert_eq!(Circuit::Shield.total_len_v2(), 112);
        assert_eq!(Circuit::Unshield.total_len_v2(), 184);
        assert_eq!(Circuit::Transfer.total_len_v2(), 208);
        assert_eq!(Circuit::Fee.total_len_v2(), 144);
    }

    #[test]
    fn parse_minimal_transfer() {
        let mut v = vec![0u8; Circuit::Transfer.total_len()];
        v[0..6].copy_from_slice(MAGIC);
        v[6] = VERSION;
        v[7] = Circuit::Transfer as u8;
        assert_eq!(parse_public_inputs(&v).unwrap(), Circuit::Transfer);
    }

    #[test]
    fn v2_roundtrip_unshield_order() {
        let root = Fr::from(7u64);
        let elems = [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)];
        let blob = encode_public_inputs_v2(
            Circuit::Unshield,
            &V2Fields { asset_tag: [9u8; 32], merkle_root: root, amount_or_fee: 300, transparent: 400_000_000, elements: &elems },
        )
        .unwrap();
        let p = parse_public_inputs_v2(&blob).unwrap();
        assert_eq!(p.circuit, Circuit::Unshield);
        assert_eq!(p.asset_tag, [9u8; 32]);
        assert_eq!(p.values, vec![root, elems[0], elems[1], Fr::from(400_000_000u64), elems[2], Fr::from(300u64)]);
        assert!(parse_public_inputs(&blob).is_err()); // not a version-1 blob
        assert_eq!(version(&blob), Some(VERSION_2));
    }

    #[test]
    fn v2_rejects_bad_length_and_noncanonical_field() {
        let blob = encode_public_inputs_v2(
            Circuit::Shield,
            &V2Fields { asset_tag: [0u8; 32], merkle_root: Fr::from(1u64), amount_or_fee: 5, transparent: 0, elements: &[Fr::from(2u64)] },
        )
        .unwrap();
        let mut short = blob.clone();
        short.pop();
        assert!(parse_public_inputs_v2(&short).is_err());
        let mut bad = blob.clone();
        for b in &mut bad[BODY_OFF + 8..BODY_OFF + 40] {
            *b = 0xff;
        }
        assert!(parse_public_inputs_v2(&bad).is_err());
        assert!(parse_public_inputs_v2(&blob).is_ok());
    }
}
