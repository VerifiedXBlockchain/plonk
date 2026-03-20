use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use plonk_core::circuit::{verify_proof, Circuit};
use plonk_core::commitment::KZG10;
use plonk_core::error::Error as PlonkError;
use plonk_core::proof_system::pi::PublicInputs;
use plonk_core::proof_system::{Proof, ProverKey, VerifierKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

type PC = KZG10<Bls12_381>;

/// Transcript label — must match prover and `plonk_ffi` verifier.
pub const TRANSCRIPT_V0: &[u8] = b"VerifiedX_VfxPi_v0";

/// Verify-only params (SRS + VK, no proving key).
const PARAM_MAGIC_V1: &[u8] = b"VXPLNK01";
/// Full params: SRS + VK + PK — required for `prove_vfxpi_v0` / `plonk_prove_v0`.
const PARAM_MAGIC_V2: &[u8] = b"VXPLNK02";

/// SRS + trim degree bound (same as `trusted_setup_v0`).
pub const V0_SRS_DEGREE_LOG: usize = 10;

#[derive(Debug, Error)]
pub enum VfxVerifyError {
    #[error("plonk: {0:?}")]
    Plonk(PlonkError),
    #[error("serde: {0}")]
    Serde(String),
    #[error("bad params blob")]
    BadParams,
}

#[derive(Debug, Error)]
pub enum VfxProveError {
    #[error("plonk: {0:?}")]
    Plonk(PlonkError),
    #[error("serde: {0}")]
    Serde(String),
    #[error("params blob has no prover key — use VXPLNK02 from vfx_plonk_setup")]
    NoProverKey,
}

impl From<PlonkError> for VfxVerifyError {
    fn from(e: PlonkError) -> Self {
        VfxVerifyError::Plonk(e)
    }
}

/// Map full VFXPI1 public-input bytes to a field element (must match prover).
pub fn hash_vfxpi1_to_fr(pi_bytes: &[u8]) -> Fr {
    let d = Sha256::digest(pi_bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&d);
    Fr::from_le_bytes_mod_order(&arr)
}

/// Single public-input digest binding (v0). **Not** full privacy — pipeline only.
#[derive(Clone, Debug)]
pub struct VfxPiBindingV0Circuit {
    pub pi_digest: Fr,
}

impl Default for VfxPiBindingV0Circuit {
    fn default() -> Self {
        Self {
            pi_digest: Fr::zero(),
        }
    }
}

impl Circuit<Fr, JubJubParameters> for VfxPiBindingV0Circuit {
    const CIRCUIT_ID: [u8; 32] =
        *b"VFX_PI_BIND_V0__________________";

    fn gadget(
        &mut self,
        composer: &mut plonk_core::constraint_system::StandardComposer<Fr, JubJubParameters>,
    ) -> Result<(), PlonkError> {
        let zero = composer.zero_var();
        let w = composer.add_input(self.pi_digest);
        let out = composer.arithmetic_gate(|gate| {
            gate.witness(w, zero, None)
                .add(Fr::one(), Fr::zero())
                .pi(-self.pi_digest)
        });
        composer.constrain_to_constant(out, Fr::zero(), None);
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 9
    }
}

type UniversalParams = <PC as PolynomialCommitment<Fr, DensePolynomial<Fr>>>::UniversalParams;

/// Serialized SRS + keys for the v0 circuit (`vfx_plonk_setup` writes **VXPLNK02** with prover key).
#[derive(Clone)]
pub struct VfxPlonkParamsBlob {
    pub universal: UniversalParams,
    pub verifier_key: VerifierKey<Fr, PC>,
    /// Present for **VXPLNK02**; `None` for legacy **VXPLNK01** (verify-only).
    pub prover_key: Option<ProverKey<Fr>>,
    pub public_input_row: usize,
}

impl VfxPlonkParamsBlob {
    pub fn serialize(&self) -> Result<Vec<u8>, ark_serialize::SerializationError> {
        if let Some(ref pk) = self.prover_key {
            let mut out = Vec::new();
            out.extend_from_slice(PARAM_MAGIC_V2);
            let mut u = Vec::new();
            self.universal.serialize(&mut u)?;
            let mut v = Vec::new();
            self.verifier_key.serialize(&mut v)?;
            let mut p = Vec::new();
            pk.serialize(&mut p)?;
            (u.len() as u64).serialize(&mut out)?;
            out.extend_from_slice(&u);
            (v.len() as u64).serialize(&mut out)?;
            out.extend_from_slice(&v);
            (p.len() as u64).serialize(&mut out)?;
            out.extend_from_slice(&p);
            (self.public_input_row as u32).serialize(&mut out)?;
            Ok(out)
        } else {
            let mut out = Vec::new();
            out.extend_from_slice(PARAM_MAGIC_V1);
            let mut u = Vec::new();
            self.universal.serialize(&mut u)?;
            let mut v = Vec::new();
            self.verifier_key.serialize(&mut v)?;
            (u.len() as u64).serialize(&mut out)?;
            out.extend_from_slice(&u);
            (v.len() as u64).serialize(&mut out)?;
            out.extend_from_slice(&v);
            (self.public_input_row as u32).serialize(&mut out)?;
            Ok(out)
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        if bytes.len() < 8 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        if bytes.len() >= PARAM_MAGIC_V2.len() && &bytes[..PARAM_MAGIC_V2.len()] == PARAM_MAGIC_V2 {
            return Self::deserialize_v2(bytes);
        }
        if bytes.len() >= PARAM_MAGIC_V1.len() && &bytes[..PARAM_MAGIC_V1.len()] == PARAM_MAGIC_V1 {
            return Self::deserialize_v1(bytes);
        }
        Err(ark_serialize::SerializationError::InvalidData)
    }

    fn deserialize_v1(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        if bytes.len() < PARAM_MAGIC_V1.len() + 8 + 8 + 4 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut cur = PARAM_MAGIC_V1.len();
        let u_len = u64::deserialize(&bytes[cur..cur + 8])? as usize;
        cur += 8;
        let u = &bytes[cur..cur + u_len];
        cur += u_len;
        let v_len = u64::deserialize(&bytes[cur..cur + 8])? as usize;
        cur += 8;
        let v = &bytes[cur..cur + v_len];
        cur += v_len;
        let public_input_row = u32::deserialize(&bytes[cur..cur + 4])? as usize;

        let universal = UniversalParams::deserialize(u)?;
        let verifier_key = VerifierKey::<Fr, PC>::deserialize(v)?;
        Ok(VfxPlonkParamsBlob {
            universal,
            verifier_key,
            prover_key: None,
            public_input_row,
        })
    }

    fn deserialize_v2(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        if bytes.len() < PARAM_MAGIC_V2.len() + 8 + 8 + 8 + 4 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut cur = PARAM_MAGIC_V2.len();
        let u_len = u64::deserialize(&bytes[cur..cur + 8])? as usize;
        cur += 8;
        let u = &bytes[cur..cur + u_len];
        cur += u_len;
        let v_len = u64::deserialize(&bytes[cur..cur + 8])? as usize;
        cur += 8;
        let v = &bytes[cur..cur + v_len];
        cur += v_len;
        let p_len = u64::deserialize(&bytes[cur..cur + 8])? as usize;
        cur += 8;
        let p = &bytes[cur..cur + p_len];
        cur += p_len;
        let public_input_row = u32::deserialize(&bytes[cur..cur + 4])? as usize;

        let universal = UniversalParams::deserialize(u)?;
        let verifier_key = VerifierKey::<Fr, PC>::deserialize(v)?;
        let prover_key = ProverKey::<Fr>::deserialize(p)?;
        Ok(VfxPlonkParamsBlob {
            universal,
            verifier_key,
            prover_key: Some(prover_key),
            public_input_row,
        })
    }
}

/// Verify a PLONK proof against `pi_bytes` (full VFXPI1 blob) using v0 digest binding.
pub fn verify_vfxpi_v0(
    params: &VfxPlonkParamsBlob,
    proof_bytes: &[u8],
    pi_bytes: &[u8],
) -> Result<(), VfxVerifyError> {
    let digest = hash_vfxpi1_to_fr(pi_bytes);
    // Must match `VfxPiBindingV0Circuit::gadget`: `.pi(-self.pi_digest)`.
    let neg_digest = -digest;
    let mut public_inputs = PublicInputs::new();
    public_inputs
        .add_input(params.public_input_row, &neg_digest)
        .map_err(|e| VfxVerifyError::Serde(format!("{:?}", e)))?;

    let proof = Proof::<Fr, PC>::deserialize(proof_bytes)
        .map_err(|e| VfxVerifyError::Serde(format!("proof: {:?}", e)))?;

    verify_proof::<Fr, JubJubParameters, PC>(
        &params.universal,
        params.verifier_key.clone(),
        &proof,
        &public_inputs,
        TRANSCRIPT_V0,
    )
    .map_err(VfxVerifyError::from)
}

/// Produce a canonical PLONK proof byte vector for `pi_bytes` (full VFXPI1 blob).
pub fn prove_vfxpi_v0(
    params: &VfxPlonkParamsBlob,
    pi_bytes: &[u8],
) -> Result<Vec<u8>, VfxProveError> {
    let pk = params
        .prover_key
        .as_ref()
        .ok_or(VfxProveError::NoProverKey)?;
    let digest = hash_vfxpi1_to_fr(pi_bytes);
    let mut circuit = VfxPiBindingV0Circuit { pi_digest: digest };
    let (proof, _pi) = circuit
        .gen_proof::<PC>(&params.universal, pk.clone(), TRANSCRIPT_V0)
        .map_err(VfxProveError::Plonk)?;
    let mut buf = Vec::new();
    proof
        .serialize(&mut buf)
        .map_err(|e| VfxProveError::Serde(format!("{:?}", e)))?;
    Ok(buf)
}

/// Run trusted setup for v0, compile circuit, return blob to serialize (**VXPLNK02** with prover key).
pub fn trusted_setup_v0() -> Result<VfxPlonkParamsBlob, PlonkError> {
    let mut circuit = VfxPiBindingV0Circuit::default();
    let pp = PC::setup(1 << V0_SRS_DEGREE_LOG, None, &mut OsRng)
        .map_err(plonk_core::error::to_pc_error::<Fr, PC>)?;
    let (pk, (vk, pi_pos)) = circuit.compile::<PC>(&pp)?;
    let row = *pi_pos
        .first()
        .ok_or(PlonkError::CircuitInputsNotFound)?;
    Ok(VfxPlonkParamsBlob {
        universal: pp,
        verifier_key: vk,
        prover_key: Some(pk),
        public_input_row: row,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonk_core::circuit::VerifierData;

    #[test]
    fn v0_prove_verify_roundtrip() {
        let params = trusted_setup_v0().expect("setup");
        let pi_bytes = vec![0u8; 128];
        let digest = hash_vfxpi1_to_fr(&pi_bytes);

        let mut circuit = VfxPiBindingV0Circuit { pi_digest: digest };
        let pp = &params.universal;
        let pk = params.prover_key.clone().unwrap();

        let (proof, pi) = circuit.gen_proof::<PC>(pp, pk, TRANSCRIPT_V0).expect("prove");

        let vd = VerifierData::new(params.verifier_key.clone(), pi);
        assert!(
            verify_proof::<Fr, JubJubParameters, PC>(
                pp,
                vd.key.clone(),
                &proof,
                vd.pi(),
                TRANSCRIPT_V0,
            )
            .is_ok()
        );

        let mut proof_bytes = Vec::new();
        proof.serialize(&mut proof_bytes).unwrap();

        verify_vfxpi_v0(&params, &proof_bytes, &pi_bytes).expect("verify helper");
    }

    #[test]
    fn params_blob_roundtrip() {
        let p = trusted_setup_v0().unwrap();
        let bytes = p.serialize().unwrap();
        assert!(bytes.starts_with(b"VXPLNK02"));
        let q = VfxPlonkParamsBlob::deserialize(&bytes).unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        p.verifier_key.serialize(&mut a).unwrap();
        q.verifier_key.serialize(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(p.public_input_row, q.public_input_row);
        assert!(p.prover_key.is_some() && q.prover_key.is_some());
    }

    #[test]
    fn prove_vfxpi_v0_roundtrip_verifies() {
        let params = trusted_setup_v0().unwrap();
        let pi_bytes = vec![1u8; 128];
        let proof = prove_vfxpi_v0(&params, &pi_bytes).expect("prove_vfxpi_v0");
        verify_vfxpi_v0(&params, &proof, &pi_bytes).expect("verify");
    }
}
