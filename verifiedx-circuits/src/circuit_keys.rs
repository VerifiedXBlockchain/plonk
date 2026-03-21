//! Circuit key management for v1 privacy circuits.
//!
//! Each circuit type (Shield, Transfer, Unshield, Fee) has its own
//! ProverKey + VerifierKey, compiled from the circuit's padded size.
//! These keys are serialized into a params blob for distribution.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use plonk_core::circuit::{verify_proof, Circuit};
use plonk_core::commitment::KZG10;
use plonk_core::error::Error;
use plonk_core::proof_system::pi::PublicInputs;
use plonk_core::proof_system::{Proof, ProverKey, VerifierKey};

use crate::circuits::fee::FeeCircuit;
use crate::circuits::shield::ShieldCircuit;
use crate::circuits::transfer::TransferCircuit;
use crate::circuits::unshield::UnshieldCircuit;

type PC = KZG10<Bls12_381>;
type UniversalParams = <PC as ark_poly_commit::PolynomialCommitment<Fr, ark_poly::univariate::DensePolynomial<Fr>>>::UniversalParams;

/// Maximum circuit size across all circuit types (Transfer is largest at 2^15).
pub const MAX_CIRCUIT_SIZE: usize = 1 << 15;

/// Compiled keys for all four circuit types.
pub struct CircuitKeys {
    pub shield_pk: Option<ProverKey<Fr>>,
    pub shield_vk: VerifierKey<Fr, PC>,
    pub shield_pi_pos: Vec<usize>,

    pub transfer_pk: Option<ProverKey<Fr>>,
    pub transfer_vk: VerifierKey<Fr, PC>,
    pub transfer_pi_pos: Vec<usize>,

    pub unshield_pk: Option<ProverKey<Fr>>,
    pub unshield_vk: VerifierKey<Fr, PC>,
    pub unshield_pi_pos: Vec<usize>,

    pub fee_pk: Option<ProverKey<Fr>>,
    pub fee_vk: VerifierKey<Fr, PC>,
    pub fee_pi_pos: Vec<usize>,
}

/// Compile all circuit keys from universal params.
/// If `include_prover_keys` is false, only verifier keys are retained.
pub fn compile_all_circuits(
    pp: &UniversalParams,
    include_prover_keys: bool,
) -> Result<CircuitKeys, Error> {
    // Shield
    let mut shield = ShieldCircuit::<Fr>::default();
    let (shield_pk, (shield_vk, shield_pi_pos)) =
        <ShieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::compile::<PC>(&mut shield, pp)?;

    // Transfer
    let mut transfer = TransferCircuit::<Fr>::default();
    let (transfer_pk, (transfer_vk, transfer_pi_pos)) =
        <TransferCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::compile::<PC>(&mut transfer, pp)?;

    // Unshield
    let mut unshield = UnshieldCircuit::<Fr>::default();
    let (unshield_pk, (unshield_vk, unshield_pi_pos)) =
        <UnshieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::compile::<PC>(&mut unshield, pp)?;

    // Fee
    let mut fee = FeeCircuit::<Fr>::default();
    let (fee_pk, (fee_vk, fee_pi_pos)) =
        <FeeCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::compile::<PC>(&mut fee, pp)?;

    Ok(CircuitKeys {
        shield_pk: if include_prover_keys { Some(shield_pk) } else { None },
        shield_vk,
        shield_pi_pos,
        transfer_pk: if include_prover_keys { Some(transfer_pk) } else { None },
        transfer_vk,
        transfer_pi_pos,
        unshield_pk: if include_prover_keys { Some(unshield_pk) } else { None },
        unshield_vk,
        unshield_pi_pos,
        fee_pk: if include_prover_keys { Some(fee_pk) } else { None },
        fee_vk,
        fee_pi_pos,
    })
}

// ─── Shield prove/verify ───────────────────────────────────────────

/// Generate a Shield circuit proof.
pub fn prove_shield(
    pp: &UniversalParams,
    pk: ProverKey<Fr>,
    amount_scaled: Fr,
    randomness: Fr,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut circuit = ShieldCircuit::<Fr> {
        amount_scaled,
        randomness,
        pi_pos: Vec::new(),
    };

    let (proof, pi) = <ShieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::gen_proof::<PC>(&mut circuit, pp, pk, b"VFX_SHIELD_V1")?;

    let proof_bytes = serialize_proof(&proof)?;
    let pi_bytes = serialize_pi(&pi)?;

    Ok((proof_bytes, pi_bytes))
}

/// Verify a Shield circuit proof.
pub fn verify_shield(
    pp: &UniversalParams,
    vk: VerifierKey<Fr, PC>,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> Result<bool, Error> {
    let proof = deserialize_proof(proof_bytes)?;
    let pi = deserialize_pi(pi_bytes)?;

    match verify_proof::<Fr, EdwardsParameters, PC>(pp, vk, &proof, &pi, b"VFX_SHIELD_V1") {
        Ok(()) => Ok(true),
        Err(Error::ProofVerificationError) => Ok(false),
        Err(e) => Err(e),
    }
}

// ─── Transfer prove/verify ─────────────────────────────────────────

/// Generate a Transfer circuit proof.
pub fn prove_transfer(
    pp: &UniversalParams,
    pk: ProverKey<Fr>,
    circuit: &mut TransferCircuit<Fr>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (proof, pi) = <TransferCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::gen_proof::<PC>(circuit, pp, pk, b"VFX_TRANSFER_V1")?;

    let proof_bytes = serialize_proof(&proof)?;
    let pi_bytes = serialize_pi(&pi)?;

    Ok((proof_bytes, pi_bytes))
}

/// Verify a Transfer circuit proof.
pub fn verify_transfer(
    pp: &UniversalParams,
    vk: VerifierKey<Fr, PC>,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> Result<bool, Error> {
    let proof = deserialize_proof(proof_bytes)?;
    let pi = deserialize_pi(pi_bytes)?;

    match verify_proof::<Fr, EdwardsParameters, PC>(pp, vk, &proof, &pi, b"VFX_TRANSFER_V1") {
        Ok(()) => Ok(true),
        Err(Error::ProofVerificationError) => Ok(false),
        Err(e) => Err(e),
    }
}

// ─── Unshield prove/verify ─────────────────────────────────────────

/// Generate an Unshield circuit proof.
pub fn prove_unshield(
    pp: &UniversalParams,
    pk: ProverKey<Fr>,
    circuit: &mut UnshieldCircuit<Fr>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (proof, pi) = <UnshieldCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::gen_proof::<PC>(circuit, pp, pk, b"VFX_UNSHIELD_V1")?;

    let proof_bytes = serialize_proof(&proof)?;
    let pi_bytes = serialize_pi(&pi)?;

    Ok((proof_bytes, pi_bytes))
}

/// Verify an Unshield circuit proof.
pub fn verify_unshield(
    pp: &UniversalParams,
    vk: VerifierKey<Fr, PC>,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> Result<bool, Error> {
    let proof = deserialize_proof(proof_bytes)?;
    let pi = deserialize_pi(pi_bytes)?;

    match verify_proof::<Fr, EdwardsParameters, PC>(pp, vk, &proof, &pi, b"VFX_UNSHIELD_V1") {
        Ok(()) => Ok(true),
        Err(Error::ProofVerificationError) => Ok(false),
        Err(e) => Err(e),
    }
}

// ─── Fee prove/verify ──────────────────────────────────────────────

/// Generate a Fee circuit proof.
pub fn prove_fee(
    pp: &UniversalParams,
    pk: ProverKey<Fr>,
    circuit: &mut FeeCircuit<Fr>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (proof, pi) = <FeeCircuit<Fr> as Circuit<Fr, EdwardsParameters>>::gen_proof::<PC>(circuit, pp, pk, b"VFX_FEE_V1")?;

    let proof_bytes = serialize_proof(&proof)?;
    let pi_bytes = serialize_pi(&pi)?;

    Ok((proof_bytes, pi_bytes))
}

/// Verify a Fee circuit proof.
pub fn verify_fee(
    pp: &UniversalParams,
    vk: VerifierKey<Fr, PC>,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> Result<bool, Error> {
    let proof = deserialize_proof(proof_bytes)?;
    let pi = deserialize_pi(pi_bytes)?;

    match verify_proof::<Fr, EdwardsParameters, PC>(pp, vk, &proof, &pi, b"VFX_FEE_V1") {
        Ok(()) => Ok(true),
        Err(Error::ProofVerificationError) => Ok(false),
        Err(e) => Err(e),
    }
}

// ─── Serialization helpers ─────────────────────────────────────────

fn serialize_proof(proof: &Proof<Fr, PC>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    proof
        .serialize(&mut buf)
        .map_err(|_| Error::ProofVerificationError)?;
    Ok(buf)
}

fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Fr, PC>, Error> {
    Proof::<Fr, PC>::deserialize(bytes).map_err(|_| Error::ProofVerificationError)
}

fn serialize_pi(pi: &PublicInputs<Fr>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    pi.serialize(&mut buf)
        .map_err(|_| Error::ProofVerificationError)?;
    Ok(buf)
}

fn deserialize_pi(bytes: &[u8]) -> Result<PublicInputs<Fr>, Error> {
    PublicInputs::<Fr>::deserialize(bytes).map_err(|_| Error::ProofVerificationError)
}

// ─── Params blob (v1) ──────────────────────────────────────────────

/// Magic bytes for v1 circuit params.
pub const PARAMS_MAGIC_V1: &[u8; 8] = b"VXPLNK03";

/// Serialized params blob containing universal params + circuit keys.
pub struct ParamsBlobV1 {
    pub universal_params: Vec<u8>,
    pub shield_vk: Vec<u8>,
    pub shield_pk: Option<Vec<u8>>,
    pub transfer_vk: Vec<u8>,
    pub transfer_pk: Option<Vec<u8>>,
    pub unshield_vk: Vec<u8>,
    pub unshield_pk: Option<Vec<u8>>,
    pub fee_vk: Vec<u8>,
    pub fee_pk: Option<Vec<u8>>,
}

impl ParamsBlobV1 {
    /// Serialize to bytes: magic (8) + sections.
    /// Each section: length (4 LE) + data. Optional sections use 0 length for absent.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PARAMS_MAGIC_V1);

        // Universal params
        write_section(&mut out, &self.universal_params);

        // For each circuit: vk (required) + pk (optional)
        write_section(&mut out, &self.shield_vk);
        write_optional_section(&mut out, &self.shield_pk);

        write_section(&mut out, &self.transfer_vk);
        write_optional_section(&mut out, &self.transfer_pk);

        write_section(&mut out, &self.unshield_vk);
        write_optional_section(&mut out, &self.unshield_pk);

        write_section(&mut out, &self.fee_vk);
        write_optional_section(&mut out, &self.fee_pk);

        out
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 || &data[..8] != PARAMS_MAGIC_V1 {
            return Err("invalid magic");
        }
        let mut cursor = 8;

        let universal_params = read_section(data, &mut cursor)?;

        let shield_vk = read_section(data, &mut cursor)?;
        let shield_pk = read_optional_section(data, &mut cursor)?;

        let transfer_vk = read_section(data, &mut cursor)?;
        let transfer_pk = read_optional_section(data, &mut cursor)?;

        let unshield_vk = read_section(data, &mut cursor)?;
        let unshield_pk = read_optional_section(data, &mut cursor)?;

        let fee_vk = read_section(data, &mut cursor)?;
        let fee_pk = read_optional_section(data, &mut cursor)?;

        Ok(Self {
            universal_params,
            shield_vk,
            shield_pk,
            transfer_vk,
            transfer_pk,
            unshield_vk,
            unshield_pk,
            fee_vk,
            fee_pk,
        })
    }
}

fn write_section(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn write_optional_section(out: &mut Vec<u8>, data: &Option<Vec<u8>>) {
    match data {
        Some(d) => write_section(out, d),
        None => out.extend_from_slice(&0u32.to_le_bytes()),
    }
}

fn read_section(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, &'static str> {
    if *cursor + 4 > data.len() {
        return Err("truncated section length");
    }
    let len = u32::from_le_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        return Err("truncated section data");
    }
    let section = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(section)
}

fn read_optional_section(data: &[u8], cursor: &mut usize) -> Result<Option<Vec<u8>>, &'static str> {
    let section = read_section(data, cursor)?;
    if section.is_empty() {
        Ok(None)
    } else {
        Ok(Some(section))
    }
}