//! A malformed proof that makes the verifier panic is refused with `ERR_PANIC`; it does not abort the host. Unwinding
//! out of an `extern "C"` function aborts the process, and the verifier panics on a proof whose custom evaluations
//! lack a label (`CustomEvaluations::get`), so before every exported function caught panics a crafted private
//! transaction stopped every node that checked it. Needs the `VXPLNK06` params with prover keys (`VFX_PLONK_PARAMS`,
//! or `vfx_plonk_v4.params` in the workspace root); without them the end-to-end test returns early and says so.

use ark_bls12_381::Fr;
use plonk_ffi::{circuits_v1, plonk_verify, ERR_PANIC};

fn params_loaded() -> bool {
    let path = std::env::var("VFX_PLONK_PARAMS").ok().or_else(|| {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("vfx_plonk_v4.params");
        p.exists().then(|| p.to_string_lossy().into_owned())
    });
    let Some(path) = path else {
        eprintln!("ffi_panic_guard: no params file (set VFX_PLONK_PARAMS); end-to-end test skipped");
        return false;
    };
    let bytes = std::fs::read(&path).expect("read params");
    circuits_v1::try_load_v1_params(&bytes).expect("load VXPLNK06");
    circuits_v1::has_v1_prover_keys()
}

/// The proof with its custom-evaluation list (`Vec<(String, Fr)>`, serialized as u64 count, then per entry a u64
/// length, the label, and 32 bytes) replaced by an empty list: it still deserializes, and verification panics.
fn without_custom_evaluations(proof: &[u8]) -> Vec<u8> {
    let label_at = proof.windows(5).position(|w| w == b"_eval").expect("custom evaluation labels in the proof");
    // Walk back to the first label's length prefix, then to the list's count.
    let mut start = None;
    for s in (0..label_at).rev() {
        if s < 16 { break; }
        let len = u64::from_le_bytes(proof[s - 8..s].try_into().unwrap()) as usize;
        if len > 0 && len < 64 && s + len > label_at && proof[s..s + len].iter().all(|b| b.is_ascii_graphic()) {
            start = Some(s - 16);
            break;
        }
    }
    let start = start.expect("the custom evaluation list");
    let count = u64::from_le_bytes(proof[start..start + 8].try_into().unwrap()) as usize;
    let mut end = start + 8;
    for _ in 0..count {
        let len = u64::from_le_bytes(proof[end..end + 8].try_into().unwrap()) as usize;
        end += 8 + len + 32;
    }
    let mut out = proof[..start].to_vec();
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&proof[end..]);
    out
}

#[test]
fn a_proof_that_panics_the_verifier_is_refused_not_aborting() {
    if !params_loaded() {
        return;
    }
    let (proof, pi) = circuits_v1::ffi_prove_shield(500_000_000, Fr::from(7u64), Fr::from(11u64)).expect("prove a shield");
    assert_eq!(plonk_verify(1, proof.as_ptr(), proof.len(), pi.as_ptr(), pi.len()), 1, "the honest proof verifies");

    let crafted = without_custom_evaluations(&proof);
    let code = plonk_verify(1, crafted.as_ptr(), crafted.len(), pi.as_ptr(), pi.len());

    assert_eq!(code, ERR_PANIC);
    // The library still works afterwards (a poisoned lock does not stop later calls).
    assert_eq!(plonk_verify(1, proof.as_ptr(), proof.len(), pi.as_ptr(), pi.len()), 1);
}

#[test]
fn garbage_proof_bytes_are_refused_without_aborting() {
    let pi = vec![0u8; 64];
    for len in [1usize, 32, 300, 4096] {
        let junk: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let code = plonk_verify(1, junk.as_ptr(), junk.len(), pi.as_ptr(), pi.len());
        assert!(code <= 0, "junk of {len} bytes did not verify (got {code})");
    }
}
