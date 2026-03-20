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
use plonk_core::proof_system::{Proof, VerifierKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

type PC = KZG10<Bls12_381>;

/// Transcript label — must match prover and `plonk_ffi` verifier.
pub const TRANSCRIPT_V0: &[u8] = b"VerifiedX_VfxPi_v0";

const PARAM_MAGIC: &[u8] = b"VXPLNK01";

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

/// Serialized SRS + verifier key for the v0 circuit (written by `vfx_plonk_setup`).
#[derive(Clone)]
pub struct VfxPlonkParamsBlob {
    pub universal: UniversalParams,
    pub verifier_key: VerifierKey<Fr, PC>,
    pub public_input_row: usize,
}

impl VfxPlonkParamsBlob {
    pub fn serialize(&self) -> Result<Vec<u8>, ark_serialize::SerializationError> {
        let mut out = Vec::new();
        out.extend_from_slice(PARAM_MAGIC);
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

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ark_serialize::SerializationError> {
        if bytes.len() < PARAM_MAGIC.len() + 8 + 8 + 4 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        if &bytes[..PARAM_MAGIC.len()] != PARAM_MAGIC {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut cur = PARAM_MAGIC.len();
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

/// Run trusted setup for v0, compile circuit, return blob to serialize.
pub fn trusted_setup_v0() -> Result<VfxPlonkParamsBlob, PlonkError> {
    let mut circuit = VfxPiBindingV0Circuit::default();
    let pp = PC::setup(1 << V0_SRS_DEGREE_LOG, None, &mut OsRng)
        .map_err(plonk_core::error::to_pc_error::<Fr, PC>)?;
    let (_pk, (vk, pi_pos)) = circuit.compile::<PC>(&pp)?;
    let row = *pi_pos
        .first()
        .ok_or(PlonkError::CircuitInputsNotFound)?;
    Ok(VfxPlonkParamsBlob {
        universal: pp,
        verifier_key: vk,
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
        let (pk, (vk, pi_pos)) = circuit.compile::<PC>(pp).expect("compile");
        let row = *pi_pos
            .first()
            .expect("pi row");

        let (proof, pi) = circuit.gen_proof::<PC>(pp, pk, TRANSCRIPT_V0).expect("prove");

        let vd = VerifierData::new(vk.clone(), pi);
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

        // `verifier_key` + `public_input_row` must be from the same `compile` as `gen_proof`.
        let blob = VfxPlonkParamsBlob {
            universal: params.universal.clone(),
            verifier_key: vk,
            public_input_row: row,
        };
        verify_vfxpi_v0(&blob, &proof_bytes, &pi_bytes).expect("verify helper");
    }

    #[test]
    fn params_blob_roundtrip() {
        let p = trusted_setup_v0().unwrap();
        let bytes = p.serialize().unwrap();
        let q = VfxPlonkParamsBlob::deserialize(&bytes).unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        p.verifier_key.serialize(&mut a).unwrap();
        q.verifier_key.serialize(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(p.public_input_row, q.public_input_row);
    }
}
