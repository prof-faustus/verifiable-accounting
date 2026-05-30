// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Merkle Proof Entity over the BSV block Merkle tree.
//!
//! Implements **WO 2022/100946 A1** (the Merkle Proof Entity patent).
//!
//! ## Construction
//!
//! The patent specifies the node rule:
//!
//! - `N(i, j) = H(D_i)` when `i == j` (leaf)
//! - `N(i, j) = H(N(i, k) || N(k+1, j))` when `i != j` (internal), splitting at `k`
//!
//! On BSV the hash is double-SHA256 (`H(x) = SHA256(SHA256(x))`, see
//! [`vaa_bsv::hash::double_sha256`]) and the tree obeys the standard
//! BSV **odd-node duplication rule**: when a level has an odd number
//! of nodes, the last node is concatenated with itself before hashing. This
//! makes the level-by-level construction unambiguous and reproduces the
//! Merkle root that BSV anchors in every block header.
//!
//! ## Proof
//!
//! A Merkle proof of a leaf is exactly the pair
//! `(leaf_index, ordered list of sibling hashes)`. Verification recomputes
//! the leaf hash, walks up the tree concatenating with each sibling in the
//! order dictated by the **index bit at that level** (bit 0 → current is the
//! left child, bit 1 → current is the right child), and accepts iff the
//! recomputed root equals the anchored root.
//!
//! ## Byte order
//!
//! All `Hash` values in this crate are in internal byte order — the order in
//! which BSV hashes are concatenated. The display order (big-endian
//! hexadecimal, as seen in block explorers) is the byte-reverse. The
//! `vaa_bsv` crate provides display↔internal conversions; this crate does
//! not assume one or the other.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use vaa_bsv::hash::double_sha256;

/// A 32-byte hash digest in internal byte order (BSV double-SHA256 output).
pub type Hash = [u8; 32];

/// Errors returned by Merkle construction and verification.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MerkleError {
    /// The caller passed an empty leaf slice.
    #[error("merkle tree must have at least one leaf")]
    EmptyTree,
    /// The proof's leaf index exceeded the leaf count at proof time.
    #[error("leaf index {index} is out of range for tree of {leaf_count} leaves")]
    IndexOutOfRange {
        /// The offending index.
        index: usize,
        /// The leaf count.
        leaf_count: usize,
    },
    /// The proof did not reconstruct to the expected root.
    #[error("reconstructed root does not match the expected root")]
    RootMismatch,
}

/// Compute the BSV-canonical Merkle root over `leaves`.
///
/// `leaves` are 32-byte values in internal byte order (e.g. txids stored as
/// raw bytes, not display strings).
///
/// - For an empty slice returns [`MerkleError::EmptyTree`].
/// - For a single-leaf tree the root is the leaf itself (matches the
///   BSV convention that a one-transaction block's Merkle root equals
///   the coinbase txid).
/// - Otherwise the tree is built level by level, pairing adjacent nodes and
///   hashing their concatenation, duplicating the last node at any level
///   whose length is odd, until a single root remains.
///
/// # Errors
///
/// Returns [`MerkleError::EmptyTree`] when `leaves` is empty. No other failure
/// mode exists: the construction is total over any non-empty slice of `Hash`.
///
/// # Panics
///
/// Does not panic. The internal `expect("level is non-empty")` is guarded by
/// the `while level.len() > 1` precondition and the duplication-on-odd step.
pub fn merkle_root(leaves: &[Hash]) -> Result<Hash, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("level is non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    Ok(level[0])
}

/// A Merkle proof of inclusion of one leaf.
///
/// The proof is the minimum information needed to verify inclusion against
/// the root: the leaf's index in the original leaf vector, and the ordered
/// sibling hashes encountered while walking from the leaf up to the root.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleProof {
    /// The index of the proved leaf in the original leaf order.
    pub leaf_index: usize,
    /// Sibling hashes from the bottom of the tree up to (but excluding) the
    /// root. Ordered: `siblings[0]` is the sibling at the leaf level,
    /// `siblings[siblings.len() - 1]` is the sibling at the level just below
    /// the root.
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// Reconstruct the Merkle root implied by `leaf` and this proof.
    #[must_use]
    pub fn reconstruct_root(&self, leaf: &Hash) -> Hash {
        let mut current = *leaf;
        let mut idx = self.leaf_index;
        for sibling in &self.siblings {
            current = if idx & 1 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            idx >>= 1;
        }
        current
    }

    /// Verify that this proof reconstructs to `expected_root` when starting
    /// from `leaf`. Returns [`MerkleError::RootMismatch`] on any discrepancy.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::RootMismatch`] iff the recomputed root differs
    /// from `expected_root`. Never panics, even for an oversized `leaf_index`
    /// or a proof with more siblings than the tree depth.
    pub fn verify(&self, leaf: &Hash, expected_root: &Hash) -> Result<(), MerkleError> {
        if &self.reconstruct_root(leaf) == expected_root {
            Ok(())
        } else {
            Err(MerkleError::RootMismatch)
        }
    }
}

/// Generate a Merkle proof for the leaf at `index`.
///
/// The returned proof matches the verifier the [`MerkleProof::verify`] method
/// implements: `merkle_proof(leaves, i).verify(&leaves[i], &merkle_root(leaves)?)` is
/// always `Ok(())`.
///
/// # Errors
///
/// - [`MerkleError::EmptyTree`] when `leaves` is empty.
/// - [`MerkleError::IndexOutOfRange`] when `index >= leaves.len()`.
///
/// # Panics
///
/// Does not panic; the same level-non-empty invariant as [`merkle_root`] holds.
pub fn merkle_proof(leaves: &[Hash], index: usize) -> Result<MerkleProof, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange {
            index,
            leaf_count: leaves.len(),
        });
    }
    let mut siblings: Vec<Hash> = Vec::new();
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("level is non-empty");
            level.push(last);
        }
        let sibling_idx = idx ^ 1;
        siblings.push(level[sibling_idx]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
        idx >>= 1;
    }
    Ok(MerkleProof {
        leaf_index: index,
        siblings,
    })
}

/// Hash `left || right` (each 32 bytes) with BSV double-SHA256.
#[inline]
fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    double_sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a 64-character hex string into a `Hash`.
    fn h(s: &str) -> Hash {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), 32, "must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Distinct synthetic leaves for the small-tree cases. The exact bytes
    /// don't matter — they only need to be 32-byte values that round-trip
    /// through the construction.
    fn leaves(n: usize) -> Vec<Hash> {
        let n_u8 = u8::try_from(n).expect("test leaves count fits in u8");
        (1..=n_u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[31] = i;
                h
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Unit tests
    // ------------------------------------------------------------------

    #[test]
    fn empty_tree_errors() {
        assert_eq!(merkle_root(&[]).unwrap_err(), MerkleError::EmptyTree);
        assert_eq!(merkle_proof(&[], 0).unwrap_err(), MerkleError::EmptyTree);
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let l = leaves(1);
        let root = merkle_root(&l).unwrap();
        assert_eq!(root, l[0]);
    }

    #[test]
    fn single_leaf_proof_has_no_siblings_and_verifies() {
        let l = leaves(1);
        let root = merkle_root(&l).unwrap();
        let proof = merkle_proof(&l, 0).unwrap();
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.leaf_index, 0);
        proof.verify(&l[0], &root).unwrap();
    }

    #[test]
    fn two_leaf_round_trip() {
        let l = leaves(2);
        let root = merkle_root(&l).unwrap();
        let expected_root = hash_pair(&l[0], &l[1]);
        assert_eq!(root, expected_root);

        for i in 0..2 {
            let proof = merkle_proof(&l, i).unwrap();
            assert_eq!(proof.siblings.len(), 1);
            proof.verify(&l[i], &root).unwrap();
        }
    }

    #[test]
    fn three_leaf_uses_odd_node_duplication() {
        // [A, B, C] → pad to [A, B, C, C] → [H(A||B), H(C||C)] → root
        let l = leaves(3);
        let root = merkle_root(&l).unwrap();
        let ab = hash_pair(&l[0], &l[1]);
        let cc = hash_pair(&l[2], &l[2]);
        let expected_root = hash_pair(&ab, &cc);
        assert_eq!(root, expected_root);

        for i in 0..3 {
            let proof = merkle_proof(&l, i).unwrap();
            proof.verify(&l[i], &root).unwrap();
        }
    }

    #[test]
    fn four_leaf_balanced_tree() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let ab = hash_pair(&l[0], &l[1]);
        let cd = hash_pair(&l[2], &l[3]);
        let expected_root = hash_pair(&ab, &cd);
        assert_eq!(root, expected_root);

        for i in 0..4 {
            let proof = merkle_proof(&l, i).unwrap();
            assert_eq!(proof.siblings.len(), 2);
            proof.verify(&l[i], &root).unwrap();
        }
    }

    #[test]
    fn seven_leaf_odd_duplication_at_multiple_levels() {
        // 7 → 8 (dup leaf 6) → 4 → 2 → 1
        let l = leaves(7);
        let root = merkle_root(&l).unwrap();
        for i in 0..7 {
            let proof = merkle_proof(&l, i).unwrap();
            proof.verify(&l[i], &root).unwrap();
        }
    }

    /// BSV genesis block has a single transaction (the coinbase), so
    /// its Merkle root equals the coinbase txid. This is a known-vector test
    /// that documents the single-leaf convention and the byte-order choice.
    ///
    /// Coinbase txid display (big-endian, as shown on a BSV block explorer):
    /// `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
    ///
    /// In internal byte order (the bytes BSV concatenates when
    /// hashing), the same value reversed:
    /// `3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a`
    #[test]
    fn bsv_genesis_block_merkle_root() {
        let coinbase_internal =
            h("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        let root = merkle_root(&[coinbase_internal]).unwrap();
        assert_eq!(root, coinbase_internal);
    }

    /// A real BSV mainnet block with two transactions. Source data committed
    /// at `vectors/merkle/bsv_block_v1.json`, fetched live from a public BSV
    /// explorer.
    ///
    /// This exercises:
    ///   - real BSV-anchored Merkle root reconstruction,
    ///   - the display↔internal byte-order conversion,
    ///   - even-count duplication (2 leaves → 1 pair → root),
    ///   - proof generation and verification for each of the two leaves.
    #[test]
    fn bsv_mainnet_block_merkle_root() {
        // txids in display (big-endian) form, as shown by any BSV explorer.
        let tx0_display = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082";
        let tx1_display = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
        // Expected root in display form (BSV header field).
        let expected_root_display =
            "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff";

        // BSV hashes in internal byte order are the display bytes reversed.
        let reverse = |s: &str| -> Hash {
            let mut bytes = hex::decode(s).unwrap();
            bytes.reverse();
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        };

        let leaves = [reverse(tx0_display), reverse(tx1_display)];
        let expected_root = reverse(expected_root_display);

        let root = merkle_root(&leaves).unwrap();
        assert_eq!(
            root, expected_root,
            "BSV mainnet block merkle root must match"
        );

        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i).unwrap();
            proof.verify(&leaves[i], &root).unwrap();
        }
    }

    // ------------------------------------------------------------------
    // Adversarial tests (named cases for the negative paths)
    // ------------------------------------------------------------------

    #[test]
    fn wrong_index_in_proof_fails_verification() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.leaf_index = 1; // claim a different position
        assert_eq!(
            proof.verify(&l[0], &root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn wrong_root_fails_verification() {
        let l = leaves(4);
        let proof = merkle_proof(&l, 0).unwrap();
        let bad_root = [0xffu8; 32];
        assert_eq!(
            proof.verify(&l[0], &bad_root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let proof = merkle_proof(&l, 0).unwrap();
        let mut altered = l[0];
        altered[0] ^= 1;
        assert_eq!(
            proof.verify(&altered, &root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn truncated_proof_fails_verification() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.siblings.pop();
        assert_eq!(
            proof.verify(&l[0], &root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn extra_sibling_in_proof_fails_verification() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.siblings.push([0u8; 32]);
        assert_eq!(
            proof.verify(&l[0], &root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.siblings[0][0] ^= 1;
        assert_eq!(
            proof.verify(&l[0], &root).unwrap_err(),
            MerkleError::RootMismatch
        );
    }

    #[test]
    fn index_out_of_range_errors() {
        let l = leaves(4);
        let err = merkle_proof(&l, 4).unwrap_err();
        assert_eq!(
            err,
            MerkleError::IndexOutOfRange {
                index: 4,
                leaf_count: 4
            }
        );
    }

    /// Panic-safety: a wildly oversized index in a proof must not panic
    /// during verification — it must fail with `RootMismatch`. (`idx >>= 1`
    /// in the verifier walks the index down to zero in a bounded number of
    /// steps; we only step `siblings.len()` times.)
    #[test]
    fn maximum_leaf_index_does_not_panic_in_verifier() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        proof.leaf_index = usize::MAX;
        let err = proof.verify(&l[0], &root).unwrap_err();
        assert_eq!(err, MerkleError::RootMismatch);
    }

    /// Panic-safety: a proof can have any length and the verifier never panics.
    #[test]
    fn over_long_proof_fails_with_root_mismatch_not_panic() {
        let l = leaves(4);
        let root = merkle_root(&l).unwrap();
        let mut proof = merkle_proof(&l, 0).unwrap();
        for _ in 0..100 {
            proof.siblings.push([0xa5u8; 32]);
        }
        let err = proof.verify(&l[0], &root).unwrap_err();
        assert_eq!(err, MerkleError::RootMismatch);
    }

    // ------------------------------------------------------------------
    // Property tests
    // ------------------------------------------------------------------

    mod property {
        use super::*;
        use proptest::prelude::*;

        fn arb_hash() -> impl Strategy<Value = Hash> {
            prop::array::uniform32(any::<u8>())
        }

        fn arb_leaves_and_index() -> impl Strategy<Value = (Vec<Hash>, usize)> {
            prop::collection::vec(arb_hash(), 1..50).prop_flat_map(|v| {
                let len = v.len();
                (Just(v), 0..len)
            })
        }

        proptest! {
            #[test]
            fn all_proofs_round_trip((leaves, index) in arb_leaves_and_index()) {
                let root = merkle_root(&leaves).unwrap();
                let proof = merkle_proof(&leaves, index).unwrap();
                prop_assert_eq!(proof.leaf_index, index);
                prop_assert!(proof.verify(&leaves[index], &root).is_ok());
            }

            #[test]
            fn proof_depth_bounded_by_log2(
                (leaves, index) in arb_leaves_and_index()
            ) {
                let proof = merkle_proof(&leaves, index).unwrap();
                let n = leaves.len();
                let bits = if n <= 1 { 0 } else { (n - 1).ilog2() as usize + 1 };
                prop_assert!(proof.siblings.len() <= bits);
            }

            #[test]
            fn altered_leaf_fails((leaves, index) in arb_leaves_and_index()) {
                prop_assume!(leaves.len() > 1);
                let root = merkle_root(&leaves).unwrap();
                let proof = merkle_proof(&leaves, index).unwrap();
                let mut altered = leaves[index];
                altered[0] ^= 1;
                prop_assert!(proof.verify(&altered, &root).is_err());
            }

            #[test]
            fn altered_sibling_fails((leaves, index) in arb_leaves_and_index()) {
                prop_assume!(leaves.len() > 1);
                let root = merkle_root(&leaves).unwrap();
                let mut proof = merkle_proof(&leaves, index).unwrap();
                prop_assume!(!proof.siblings.is_empty());
                proof.siblings[0][0] ^= 1;
                prop_assert!(proof.verify(&leaves[index], &root).is_err());
            }

            #[test]
            fn wrong_root_fails((leaves, index) in arb_leaves_and_index()) {
                prop_assume!(leaves.len() > 1);
                let proof = merkle_proof(&leaves, index).unwrap();
                let bad = [0xa5u8; 32];
                prop_assert!(proof.verify(&leaves[index], &bad).is_err());
            }

            #[test]
            fn root_changes_when_any_leaf_changes(
                mut leaves in prop::collection::vec(arb_hash(), 2..30),
                target in 0usize..30,
            ) {
                let target = target % leaves.len();
                let original_root = merkle_root(&leaves).unwrap();
                leaves[target][0] ^= 1;
                let new_root = merkle_root(&leaves).unwrap();
                prop_assert_ne!(original_root, new_root);
            }
        }
    }
}
