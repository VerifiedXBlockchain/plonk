# VerifiedX-Core: vBTC shielded asset key (Phase 5)

On-chain private payloads use a **per-contract** `PrivateTxPayload.asset` string:

- `VFX` — native shielded pool.
- `VBTC:{SmartContractUID}` — token-scoped Merkle tree / pool row in `DB_Privacy` (see VerifiedX `VbtcPrivacyAsset` / `VBTCPrivacyService`).

The C# layer encodes the same identifier into PLONK **public inputs v1** via SHA256(`asset`) (see `PlonkPublicInputsV1.AssetTag32` in VerifiedX-Core). When implementing vBTC circuits in this repo, treat that 32-byte tag as the **contract binding** surface for proofs (alongside any additional constraints you add in-circuit).

**PLONK prove/verify** remains to be wired to real circuits; this file only documents **cross-repo naming** so Rust and C# stay aligned.
