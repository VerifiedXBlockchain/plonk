Have a look at https://keepachangelog.com/en/1.0.0/

The following are just a few examples, we will start keeping a change log for real after the 0.1 release.

# Unreleased

- **Trusted setup (re-audit, 9 Oct 2026).** `trusted_setup_v1` seeds the KZG setup from a constant, so its tau is public
  and any statement can be proven against it: VXPLNK03 and VXPLNK04 are forgeable. `zcash_setup` imports the Zcash
  Sapling Powers of Tau (`phase1radix2m{k}`, k >= 16): Lagrange points → monomial powers by a group FFT, generator and
  pairing checks, gamma = 1 (hiding unused). `vfx_plonk_setup --zcash <file>` writes **`VXPLNK05`**; the seeded setup is
  `--insecure-seeded` and writes `VXPLNK04`, which `plonk_load_params` refuses along with `VXPLNK03`.
- **v2 owner-bound circuits (VerifiedX fund-loss re-audit, Oct 2026).** A note is `Poseidon(amount, randomness, owner_pk)`
  with `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)`; a spend proves knowledge of the owner's nullifier key, so
  only the owner can spend a note and its nullifier is unique (v1 let anyone who knew a note spend it once per key).
  The Unshield circuit binds the transparent recipient (`recipient_tag`, public input 7). Params magic **`VXPLNK04`**
  (`VXPLNK03` is refused), public-input blobs **VFXPI1 version 3** (Unshield body + recipient tag), capability bit
  `PLONK_CAP_V2_CIRCUITS` (64), `plonk_prove_shield` takes `owner_pk`, output witnesses carry `owner_pk`, Unshield / Fee
  witnesses carry `change_owner_pk` (and Unshield `recipient_tag`), new exports `poseidon_owner_pk` and
  `poseidon_note_hash_v2`. Transcript labels `VFX_*_V2`.
- plonk_ffi: circuit-compatible Poseidon exports (`poseidon_hash_2`, `poseidon_hash_3`, `poseidon_note_hash`, `poseidon_merkle_zero`, `merkle_root_from_path_v1`), `plonk_verify` accepts VFXPI1 version-2 public inputs for the v1 circuits (rebuilt at the circuits' positions), capability bit `PLONK_CAP_VFXPI2_VERIFY` (32); end-to-end tests against the VXPLNK03 params (VerifiedX fund-loss audit Oct 2026, item 1 stage 2)

- Added blinder polynomials
- Added benchmarks for proving & verification processes
- Added big_arith_gate and conditional point negate
- Added Serde support using ark-serialize and derive feature