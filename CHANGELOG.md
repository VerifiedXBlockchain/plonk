Have a look at https://keepachangelog.com/en/1.0.0/

The following are just a few examples, we will start keeping a change log for real after the 0.1 release.

# Unreleased

- plonk_ffi: circuit-compatible Poseidon exports (`poseidon_hash_2`, `poseidon_hash_3`, `poseidon_note_hash`, `poseidon_merkle_zero`, `merkle_root_from_path_v1`), `plonk_verify` accepts VFXPI1 version-2 public inputs for the v1 circuits (rebuilt at the circuits' positions), capability bit `PLONK_CAP_VFXPI2_VERIFY` (32); end-to-end tests against the VXPLNK03 params (VerifiedX fund-loss audit Oct 2026, item 1 stage 2)

- Added blinder polynomials
- Added benchmarks for proving & verification processes
- Added big_arith_gate and conditional point negate
- Added Serde support using ark-serialize and derive feature