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

## v2 owner-bound circuits (VerifiedX fund-loss re-audit, Oct 2026; params `VXPLNK04`, public inputs VFXPI1 version 3)

The v1 circuits bound a note as `Poseidon(amount, randomness)` with the spending key a free witness: anyone who knew a
note (its sender always does) could spend it with any key, once per key, and the Unshield did not bind its recipient.
The v2 circuits (`verifiedx-circuits/src/circuits/*.rs`, CIRCUIT_ID `*_V2`, transcript labels `VFX_*_V2`):

- `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)` (`OWNER_PK_DOMAIN` = `b"VFX_OWNR"` little-endian),
  `note_hash = Poseidon(amount, randomness, owner_pk)`, `nullifier = Poseidon(nullifier_key, note_hash, position)`;
  every spent note proves knowledge of its owner's nullifier key, every output carries its recipient's owner key.
- Unshield gains public input 7, `recipient_tag` (the node derives it from the transparent recipient address).
- Params: `vfx_plonk_setup` writes **`VXPLNK04`** (same layout as 03, new keys; 405 MB with prover keys; deterministic
  setup). `plonk_load_params` refuses `VXPLNK03`. Capability bit **64** `PLONK_CAP_V2_CIRCUITS`.
- `plonk_verify` takes **VFXPI1 version 3** blobs only (version 2 = `ERR_PARAM`): as version 2, plus `recipient_tag` (32)
  at the end of the Unshield body (216 bytes).
- Witness wire formats: input `nullifier_key` where `viewing_key` was; outputs are 72 bytes (`+ owner_pk`); Unshield
  adds `change_owner_pk` (32) after `change_randomness` and `recipient_tag` (32) after `merkle_root` (4408 bytes); Fee
  adds `change_owner_pk` (2240 bytes); `plonk_prove_shield(amount, randomness, owner_pk, ...)`.
- New exports `poseidon_owner_pk(nullifier_key, out)` and `poseidon_note_hash_v2(amount, randomness, owner_pk, out)`.
- Tests (`tests/v1_vfxpi2.rs`, needs `VFX_PLONK_PARAMS` = the VXPLNK04 file): every circuit against a v3 blob, the public
  dummy note, and the two re-audit attacks - a note spent with another nullifier key, and a redirected unshield - both
  refused; plus the `plonk_load_params` path and capability bits.

## v1 circuits: circuit-compatible Poseidon and on-chain public inputs (VFXPI1 version 2)

Added for the Oct 2026 fund-loss audit (VerifiedX-Core item 1, stage 2). With **`VXPLNK03`** params loaded,
`plonk_capabilities` sets **bit 5 (`PLONK_CAP_VFXPI2_VERIFY` = 32)** and the following hold:

- **`poseidon_hash_2(a, b, out)`**, **`poseidon_hash_3(a, b, c, out)`**, **`poseidon_note_hash(amount_scaled, randomness, out)`**:
  the exact hashes the v1 circuits compute (`gadgets/poseidon.rs`, `note_hash.rs`, `nullifier.rs`). Field elements are 32
  little-endian bytes in arkworks canonical form, as in the `plonk_prove_*` witness blobs; a value at or above the modulus
  returns `ERR_CRYPTO`. The older `poseidon_hash` is a *chained* sponge over big-endian chunks and is **not** what the
  circuits compute for two inputs; it stays for legacy callers. `nullifier_derive_v1` equals `poseidon_hash_3(vk, note_hash, position)`.
- **`poseidon_merkle_zero(level, out)`** and **`merkle_root_from_path_v1(leaf, position, path, 1024, out)`**: the fixed-depth-32
  tree the circuits prove against. Empty slots are the zero subtree (`zero[0] = 0`, `zero[l+1] = Poseidon(zero[l], zero[l])`);
  bit `i` of the position chooses the side at level `i`. Leaves are note hashes.
- **`plonk_verify`** with the v1 circuits accepts two public-input encodings: the prover's own `PublicInputs` bytes (what
  `plonk_prove_*` returns) and a **VFXPI1 version-2 blob**, rebuilt at the circuits' public-input positions from the on-chain
  fields - the encoding a validator sends. A version-1 blob (G1 commitments) is refused with `ERR_PARAM`. Layout (see
  `src/vfxpi1.rs`): header `VFXPI1` + version `2` + circuit byte, asset tag (32), Merkle root (32), then

  | circuit  | body                                                                           | total |
  |----------|--------------------------------------------------------------------------------|-------|
  | Shield   | amount u64 LE, note_hash                                                       | 112   |
  | Unshield | fee u64, transparent u64, nullifier0, nullifier1, change_note_hash             | 184   |
  | Transfer | fee u64, nullifier0, nullifier1, out_note_hash0, out_note_hash1                | 208   |
  | Fee      | fee u64, nullifier, change_note_hash                                           | 144   |

  The asset tag is bound by the transaction hash on chain, not by the circuits.
- A one-note spend fills the circuits' second input with the public dummy note (amount 0, randomness 0), which the node
  keeps at leaf 0 of every tree; its nullifier includes the spender's viewing key, so it is spent once per spender and adds nothing.

Tests: `plonk-ffi/tests/v1_vfxpi2.rs` (needs the params file: `VFX_PLONK_PARAMS=<path>` or `vfx_plonk_v1.params` in the
workspace root; otherwise they skip). They prove each circuit, verify against a v2 blob built only from on-chain values,
and refuse tampered ones.

## ABI

Exports match `PlonkNative.cs`: `pedersen_commit`, `pedersen_verify`, `pedersen_commitment_add` (homomorphic G1 add), `poseidon_hash`, `merkle_tree_*`, `nullifier_derive`, `plonk_load_params`, `plonk_capabilities`, `plonk_verify`.

- **`plonk_load_params`**: if the file begins with **`VXPLNK01`**, it is deserialized as [`VfxPlonkParamsBlob`](../verifiedx-circuits/src/v0_pi_binding.rs) (from `cargo run -p verifiedx-circuits --bin vfx_plonk_setup`). Then **`plonk_capabilities`** sets **`PLONK_CAP_VERIFY_V1`** and **`plonk_verify`** performs real PLONK verification (**v0 digest binding** — see [`verifiedx-circuits/README.md`](../verifiedx-circuits/README.md)). Other files are stored as opaque bytes (legacy).
- If no **`VXPLNK01`** params are loaded, **`plonk_verify`** returns **`ERR_NOT_IMPLEMENTED`** after VFXPI1 layout checks (same as before for crypto).

VerifiedX **vBTC** shielded asset keys (`VBTC:{SmartContractUID}`) and PLONK public-input alignment: see **[VERIFIEDX_VBTC.md](./VERIFIEDX_VBTC.md)**.
