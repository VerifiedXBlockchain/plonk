use std::collections::HashMap;

use crate::poseidon_hash;

/// Append-only Merkle tree of leaf digests (32-byte Fr encoding), internal nodes = Poseidon(left || right).
pub struct MerkleForest {
    trees: HashMap<String, Vec<[u8; 32]>>,
}

impl MerkleForest {
    pub fn new() -> Self {
        Self {
            trees: HashMap::new(),
        }
    }

    fn leaf_digest(commitment_g1: &[u8]) -> [u8; 32] {
        poseidon_hash::hash_bytes(commitment_g1).unwrap_or([0u8; 32])
    }

    fn combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        poseidon_hash::hash_bytes(&buf).unwrap_or([0u8; 32])
    }

    pub fn add_leaf(&mut self, tree_id: &str, commitment_g1: &[u8]) -> u64 {
        let v = self.trees.entry(tree_id.to_string()).or_default();
        let pos = v.len() as u64;
        v.push(Self::leaf_digest(commitment_g1));
        pos
    }

    pub fn prove(&self, tree_id: &str, position: u64) -> Option<(Vec<u8>, [u8; 32])> {
        let leaves = self.trees.get(tree_id)?;
        if position as usize >= leaves.len() {
            return None;
        }
        let mut proof: Vec<u8> = Vec::new();
        let mut idx = position as usize;
        let mut level: Vec<[u8; 32]> = leaves.clone();
        while level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };
            proof.extend_from_slice(&sibling);
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    left
                };
                next.push(Self::combine(&left, &right));
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Some((proof, level[0]))
    }
}

impl Default for MerkleForest {
    fn default() -> Self {
        Self::new()
    }
}
