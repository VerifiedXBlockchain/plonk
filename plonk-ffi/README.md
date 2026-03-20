# plonk_ffi (VerifiedX privacy primitives)

Thin **C ABI** (`cdylib`) used by **VerifiedX-Core** via `ReserveBlockCore/Privacy/PlonkNative.cs`. It links against this workspace’s **`plonk-hashing`** Poseidon (WIDTH 3) so hashes stay aligned with PLONK circuits.

## Deployment (VerifiedX-Core)

Run **“Build Native Libraries (plonk_ffi)”** (Actions → manual *workflow_dispatch*): it builds **Windows, Linux, and macOS** in parallel and uploads three artifacts. Copy into `VerifiedX-Core/ReserveBlockCore/Plonk/{win,linux,mac}/` — see **[DEPLOYMENT.md](./DEPLOYMENT.md)**. You can still build the DLL locally (below) if you prefer.

## Build (Windows x64)

From this directory’s parent (`plonk` workspace root), with Rust **1.83+** (see `rust-toolchain.toml`):

```powershell
cargo build -p plonk_ffi --release
```

Copy the DLL into VerifiedX-Core (same pattern as FROST):

`target/release/plonk_ffi.dll` → `VerifiedX-Core/ReserveBlockCore/Plonk/win/plonk_ffi.dll`

## Build (Linux x64)

```bash
cargo build -p plonk_ffi --release
cp target/release/libplonk_ffi.so /path/to/VerifiedX-Core/ReserveBlockCore/Plonk/linux/
```

## Build (macOS)

```bash
cargo build -p plonk_ffi --release
cp target/release/libplonk_ffi.dylib /path/to/VerifiedX-Core/ReserveBlockCore/Plonk/mac/
```

## ABI

Exports match `PlonkNative.cs`: `pedersen_commit`, `pedersen_verify`, `pedersen_commitment_add` (homomorphic G1 add), `poseidon_hash`, `merkle_tree_*`, `nullifier_derive`, `plonk_load_params`, `plonk_capabilities`, `plonk_verify`.

- **`plonk_load_params`**: if the file begins with **`VXPLNK01`**, it is deserialized as [`VfxPlonkParamsBlob`](../verifiedx-circuits/src/v0_pi_binding.rs) (from `cargo run -p verifiedx-circuits --bin vfx_plonk_setup`). Then **`plonk_capabilities`** sets **`PLONK_CAP_VERIFY_V1`** and **`plonk_verify`** performs real PLONK verification (**v0 digest binding** — see [`verifiedx-circuits/README.md`](../verifiedx-circuits/README.md)). Other files are stored as opaque bytes (legacy).
- If no **`VXPLNK01`** params are loaded, **`plonk_verify`** returns **`ERR_NOT_IMPLEMENTED`** after VFXPI1 layout checks (same as before for crypto).

VerifiedX **vBTC** shielded asset keys (`VBTC:{SmartContractUID}`) and PLONK public-input alignment: see **[VERIFIEDX_VBTC.md](./VERIFIEDX_VBTC.md)**.
