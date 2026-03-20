# verifiedx-circuits

PLONK circuits for **VerifiedX** (`PlonkPublicInputsV1` / VFXPI1), built on the workspace [`plonk-core`](../plonk-core) (BLS12-381 + KZG10).

## v0 — PI digest binding (pipeline / dev)

The first circuit proves only that the prover knows a witness consistent with **one public field element** derived as:

`Fr::from_le_bytes_mod_order(SHA256(VFXPI1_bytes)[..32])`

The in-circuit constraint binds a witness to `-H` via the standard PLONK public-input mechanism (see `VfxPiBindingV0Circuit`).

**This is not production privacy.** It does not check Pedersen amounts, Merkle paths, or nullifiers. It exists to:

- Lock the **proof ↔ public-input bytes ↔ verifier** pipeline.
- Allow `plonk_ffi` to return **`plonk_verify == 1`** when a `VXPLNK01` params file is loaded.

### Params file (`VXPLNK01`)

Generate with:

```bash
cargo run -p verifiedx-circuits --bin vfx_plonk_setup --release -- path/to/vfx_plonk_v0.params
```

Load from nodes via existing `plonk_load_params` / `VFX_PLONK_PARAMS_PATH`. The file starts with magic `VXPLNK01` and deserializes to `VfxPlonkParamsBlob` (SRS + verifier key + public-input row index).

### Proving

The **prover key** is not shipped in the v0 params blob. Wallets should either:

- Run a future `plonk_prove_*` FFI that performs `compile` + `gen_proof` with the same SRS source, or  
- Call into this crate from a Rust tool.

Use transcript label **`VerifiedX_VfxPi_v0`** (see `TRANSCRIPT_V0`).

## Next

- Shield / Unshield / Transfer / Fee circuits with real constraints aligned to VerifiedX `PlonkPublicInputsV1` (C#).
