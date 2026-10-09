//! Native Poseidon with the exact semantics of the v1 circuits (`verifiedx-circuits::gadgets::poseidon`):
//! a direct two-input Poseidon (width 3, `PoseidonConstants::generate::<3>()`), and the three-input form
//! chained from zero the way `poseidon_hash_3` is in-circuit.
//!
//! This is what the Core node and wallet must use for note hashes, Merkle parents and nullifiers so that
//! the values they put on chain are the values the circuits compute. The older `poseidon_hash` export
//! (`poseidon_hash.rs`) is a *chained* sponge over big-endian chunks starting from state 0 and is NOT
//! circuit-compatible for two inputs; it is kept for the legacy callers that depend on it.
//!
//! Field elements cross the FFI as 32 little-endian bytes in arkworks canonical form, exactly as the
//! `plonk_prove_*` witness blobs do; a value at or above the modulus is refused.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use once_cell::sync::Lazy;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use plonk_hashing::poseidon::poseidon_ref::NativeSpecRef;
use plonk_hashing::poseidon::zprize_constraints::PoseidonZZRef;

/// Depth of the commitment Merkle tree the circuits verify against.
pub const TREE_DEPTH: usize = verifiedx_circuits::gadgets::merkle::TREE_DEPTH;

const WIDTH_3: usize = 3;

static CONSTANTS_W3: Lazy<PoseidonConstants<Fr>> = Lazy::new(|| PoseidonConstants::generate::<WIDTH_3>());

/// `Poseidon(left, right)` as the circuits' `poseidon_hash_2` computes it (ZZ reference permutation, native field ops).
pub fn hash_2(left: Fr, right: Fr) -> Fr {
    let mut com = ();
    let mut p = PoseidonZZRef::<(), NativeSpecRef<Fr>, WIDTH_3>::new(&mut com, CONSTANTS_W3.clone());
    p.input(left).expect("poseidon input left");
    p.input(right).expect("poseidon input right");
    p.output_hash(&mut com)
}

/// `Poseidon(a, b, c)` as the circuits' `poseidon_hash_3` computes it: `h2(h2(h2(0, a), b), c)`.
pub fn hash_3(a: Fr, b: Fr, c: Fr) -> Fr {
    let h = hash_2(Fr::zero(), a);
    let h = hash_2(h, b);
    hash_2(h, c)
}

/// `note_hash = Poseidon(amount_scaled, randomness)` — the v1 note (no owner). Legacy helper; no v2 circuit uses it.
pub fn note_hash(amount_scaled: u64, randomness: Fr) -> Fr {
    hash_2(Fr::from(amount_scaled), randomness)
}

/// `nullifier = Poseidon(nullifier_key, note_hash, position)` — the circuits' `nullifier_gadget`. In the v2
/// circuits the key is the owner's nullifier key (whose `owner_pk` is inside the note).
pub fn nullifier(nullifier_key: Fr, note_hash: Fr, tree_position: u64) -> Fr {
    hash_3(nullifier_key, note_hash, Fr::from(tree_position))
}

/// Domain separator of `owner_pk` (re-exported from the circuits).
pub const OWNER_PK_DOMAIN: u64 = verifiedx_circuits::gadgets::note_hash::OWNER_PK_DOMAIN;

/// `owner_pk = Poseidon(OWNER_PK_DOMAIN, nullifier_key)` — the circuits' `owner_pk_gadget`.
pub fn owner_pk(nullifier_key: Fr) -> Fr {
    hash_2(Fr::from(OWNER_PK_DOMAIN), nullifier_key)
}

/// `note_hash = Poseidon(amount_scaled, randomness, owner_pk)` — the v2 note (owner-bound), the Merkle leaf.
pub fn note_hash_v2(amount_scaled: u64, randomness: Fr, owner_pk: Fr) -> Fr {
    hash_3(Fr::from(amount_scaled), randomness, owner_pk)
}

/// Canonical little-endian field element (refuses values at or above the modulus, like the prover does).
pub fn fr_from_le_canonical(bytes: &[u8]) -> Result<Fr, ()> {
    if bytes.len() != 32 {
        return Err(());
    }
    Fr::deserialize(bytes).map_err(|_| ())
}

/// 32 little-endian bytes of a field element (arkworks canonical form).
pub fn fr_to_le(fr: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    fr.serialize(&mut out[..]).expect("Fr serializes to 32 bytes");
    out
}

/// `zero[0] = 0`, `zero[l + 1] = Poseidon(zero[l], zero[l])`: the digest of an empty subtree of height `l`.
pub fn zero_hashes() -> Vec<Fr> {
    let mut z = Vec::with_capacity(TREE_DEPTH + 1);
    z.push(Fr::zero());
    for l in 0..TREE_DEPTH {
        let prev = z[l];
        z.push(hash_2(prev, prev));
    }
    z
}

/// Recomputes the root from a leaf, its position and a `TREE_DEPTH`-long sibling path, exactly as
/// `merkle_path_verify` does in-circuit (bit `i` of the position selects the side at level `i`).
pub fn root_from_path(leaf: Fr, position: u64, path: &[Fr]) -> Result<Fr, ()> {
    if path.len() != TREE_DEPTH {
        return Err(());
    }
    let mut cur = leaf;
    for (i, sibling) in path.iter().enumerate() {
        cur = if (position >> i) & 1 == 0 { hash_2(cur, *sibling) } else { hash_2(*sibling, cur) };
    }
    Ok(cur)
}

/// A fixed-depth-32 append-only Merkle tree over note hashes, with empty subtrees as `zero_hashes()`.
/// This is the tree shape the circuits prove against; the node keeps the same shape per asset.
pub struct FixedDepthTree {
    leaves: Vec<Fr>,
    zeros: Vec<Fr>,
}

impl FixedDepthTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new(), zeros: zero_hashes() }
    }

    pub fn from_leaves(leaves: Vec<Fr>) -> Self {
        Self { leaves, zeros: zero_hashes() }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn push(&mut self, leaf: Fr) -> u64 {
        self.leaves.push(leaf);
        (self.leaves.len() - 1) as u64
    }

    /// Root of the tree with every unused slot an empty subtree.
    pub fn root(&self) -> Fr {
        if self.leaves.is_empty() {
            return self.zeros[TREE_DEPTH];
        }
        let mut level = self.leaves.clone();
        for l in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for i in (0..level.len()).step_by(2) {
                let left = level[i];
                let right = if i + 1 < level.len() { level[i + 1] } else { self.zeros[l] };
                next.push(hash_2(left, right));
            }
            level = next;
        }
        level[0]
    }

    /// Sibling path (bottom-up) for the leaf at `position`.
    pub fn path(&self, position: u64) -> Result<[Fr; TREE_DEPTH], ()> {
        let idx = position as usize;
        if idx >= self.leaves.len() {
            return Err(());
        }
        let mut path = [Fr::zero(); TREE_DEPTH];
        let mut level = self.leaves.clone();
        let mut cur = idx;
        for l in 0..TREE_DEPTH {
            let sib = cur ^ 1;
            path[l] = if sib < level.len() { level[sib] } else { self.zeros[l] };
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for i in (0..level.len()).step_by(2) {
                let left = level[i];
                let right = if i + 1 < level.len() { level[i + 1] } else { self.zeros[l] };
                next.push(hash_2(left, right));
            }
            level = next;
            cur >>= 1;
        }
        Ok(path)
    }
}

impl Default for FixedDepthTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_2_is_deterministic_and_order_sensitive() {
        let a = Fr::from(42u64);
        let b = Fr::from(99u64);
        assert_eq!(hash_2(a, b), hash_2(a, b));
        assert_ne!(hash_2(a, b), hash_2(b, a));
    }

    #[test]
    fn path_recomputes_root_for_every_leaf() {
        let mut t = FixedDepthTree::new();
        for i in 1..=5u64 {
            t.push(note_hash(i * 100, Fr::from(i)));
        }
        let root = t.root();
        for pos in 0..5u64 {
            let path = t.path(pos).unwrap();
            assert_eq!(root_from_path(t.leaves[pos as usize], pos, &path).unwrap(), root);
        }
        assert!(t.path(5).is_err());
    }

    #[test]
    fn le_roundtrip_and_canonical_refusal() {
        let x = Fr::from(123456789u64);
        assert_eq!(fr_from_le_canonical(&fr_to_le(&x)).unwrap(), x);
        let mut too_big = [0xffu8; 32];
        too_big[31] = 0xff;
        assert!(fr_from_le_canonical(&too_big).is_err());
    }
}
