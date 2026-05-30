// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Selective verification / proof-sharding layer.
//!
//! Implements **WO 2025/119666 A1** ("Method and System for Enabling
//! Verification of Data"), claims 1–12.
//!
//! ## Claim mapping
//!
//! | Patent claim | Surface in this crate |
//! |---|---|
//! | **1** | [`ProofStore::anchor`] generates the Merkle proof (first data) for the indexed second data and stores it; the returned root is what the caller anchors on BSV (publication of third data). |
//! | **2–3** | [`ProofShard`] — non-overlapping portions of the proof, ordered by `from_level`; recombination by [`StoredProof::reassemble`]. |
//! | **4** | The store is indexed by [`IndexKey`]; the keys are derived from the same on-chain third data (txid / position / scripts / amount) that the patent names. |
//! | **5–6** | [`IndexKey`] carries the index-schema fields the patent enumerates: txid, in/out flag, in/out position, position of the tx in the block, locking script, unlocking script, amount. |
//! | **7** | The "function used to determine the proof" is the BSV double-SHA256 Merkle construction in [`vaa_merkle`]; the function is fixed for this project (see `docs/DECISIONS.md` D-002). |
//! | **8** | [`ProofAssistance`] — node labels at the predetermined level `k`, computed at anchor time and queryable from the store. A verifier can reconstruct a truncated path up to level `k` and complete it against these public labels. |
//! | **9–11** | EC-point homomorphic compression of the level-`k` labels on the BSV curve. Exposed only behind [`ReconstructionMode::TrustedOperational`]; this version returns `TrustedOperationalNotImplemented` and the audit path never accepts results from this mode. |
//! | **12** | [`ProofStore::query`] returns the stored proof in response to an index-key query. |
//!
//! ## Two assurance modes
//!
//! - [`ReconstructionMode::Adversarial`] (default): ordinary Merkle reconstruction
//!   against the published node labels and the on-chain root. **The only mode
//!   that yields independent audit evidence.**
//! - [`ReconstructionMode::TrustedOperational`] (opt-in): EC-point homomorphic
//!   compression. Faster but **not** adversarially secure; for internal
//!   efficiency / error detection in trusted operational environments only.
//!   Selecting this mode requires an explicit argument; there is no silent
//!   fallback. Currently returns
//!   [`ProofStoreError::TrustedOperationalNotImplemented`].

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use std::collections::HashMap;

use vaa_bsv::hash::double_sha256;
use vaa_merkle::{merkle_proof, merkle_root, Hash, MerkleError, MerkleProof};

/// Errors returned by the proofstore layer.
#[derive(Debug, thiserror::Error)]
pub enum ProofStoreError {
    /// The underlying Merkle layer rejected the input or proof.
    #[error("merkle layer error: {0}")]
    Merkle(#[from] MerkleError),

    /// No proof is stored under the supplied index key.
    #[error("no proof stored under the requested index key")]
    KeyNotFound,

    /// Reconstruction did not match the expected anchored root.
    #[error("reconstructed root does not match the expected anchored root")]
    RootMismatch,

    /// Trusted-operational mode (EC-point compression, claims 9–11) is not
    /// implemented in this crate version. Use [`ReconstructionMode::Adversarial`].
    #[error(
        "trusted-operational EC-compression mode is not implemented in this version; \
         use ReconstructionMode::Adversarial for audit-mode verification"
    )]
    TrustedOperationalNotImplemented,

    /// The stored proof's reassembled shards do not match the published
    /// proof-assistance at the predetermined level.
    #[error("proof-assistance check failed: computed level-k node does not match published label")]
    AssistanceMismatch,
}

/// Which side of a BSV transaction the index entry refers to (input or output).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    /// Indexes a transaction input (unlocking-script side).
    Input,
    /// Indexes a transaction output (locking-script side).
    Output,
}

/// Index schema for stored proofs (WO 2025/119666, claims 5–6).
///
/// All fields except `txid`, `direction`, `position`, and `block_position` are
/// optional. A lookup must specify the same fields used when the proof was
/// stored; this struct's `Eq`/`Hash` is field-exact.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IndexKey {
    /// BSV txid in internal (little-endian) byte order — matches `vaa_merkle::Hash`.
    pub txid: Hash,
    /// Whether this entry is for an input or an output.
    pub direction: Direction,
    /// Position within the inputs (if `Direction::Input`) or outputs
    /// (if `Direction::Output`) of the transaction.
    pub position: u32,
    /// Position of the transaction in the block (leaf index of the tx in the
    /// block Merkle tree).
    pub block_position: u32,
    /// Locking script bytes, if the lookup wants to bind a specific script.
    pub locking_script: Option<Vec<u8>>,
    /// Unlocking script bytes, if applicable.
    pub unlocking_script: Option<Vec<u8>>,
    /// Output amount in minor units, if known.
    pub amount: Option<u64>,
}

/// Reconstruction mode selected when verifying a stored proof.
///
/// **Default is `Adversarial`.** `TrustedOperational` must be selected
/// explicitly; the verifier-facing API in `vaa-api` rejects any result that
/// did not use `Adversarial` mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum ReconstructionMode {
    /// Ordinary Merkle reconstruction. Adversarially sound. Default.
    #[default]
    Adversarial,
    /// EC-point homomorphic compression (WO 2025/119666 claims 9–11).
    /// **Not** adversarially secure. Opt-in. Not yet implemented in this
    /// crate version.
    TrustedOperational,
}

/// A non-overlapping portion of a Merkle proof (WO 2025/119666 claims 2–3).
///
/// `from_level` is the inclusive starting tree level (0 = leaf level);
/// `to_level` is the exclusive ending level. The vector `siblings` carries
/// exactly `to_level - from_level` entries, each the sibling at the
/// corresponding level when walking from leaf to root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofShard {
    /// Inclusive level this shard starts at (0 = adjacent to the leaf).
    pub from_level: usize,
    /// Exclusive level this shard ends at.
    pub to_level: usize,
    /// Ordered sibling hashes for levels `[from_level, to_level)`.
    pub siblings: Vec<Hash>,
}

impl ProofShard {
    /// Number of levels (== number of siblings) covered by this shard.
    #[must_use]
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    /// Whether this shard carries any siblings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }
}

/// The bundle stored by the proofstore for one indexed query target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredProof {
    /// The index key under which this proof is stored.
    pub key: IndexKey,
    /// The leaf index that the proof witnesses inclusion of.
    pub leaf_index: usize,
    /// Non-overlapping shards of the Merkle proof, ordered ascending by
    /// `from_level`. Concatenating the shards' siblings reconstitutes the
    /// full proof. May be empty (single-leaf tree).
    pub shards: Vec<ProofShard>,
    /// Anchored Merkle root the proof must reconstruct to.
    pub expected_root: Hash,
}

impl StoredProof {
    /// Reassemble the shards into a single ordered Merkle proof.
    #[must_use]
    pub fn reassemble(&self) -> MerkleProof {
        let mut siblings = Vec::new();
        for shard in &self.shards {
            siblings.extend_from_slice(&shard.siblings);
        }
        MerkleProof {
            leaf_index: self.leaf_index,
            siblings,
        }
    }
}

/// Public proof-assistance data published alongside the on-chain anchor
/// (WO 2025/119666 claim 8).
///
/// The labels are the Merkle-tree node hashes at level
/// `predetermined_level`. A verifier may reconstruct from leaf up to this
/// level using stored shards, then complete the verification against these
/// public labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofAssistance {
    /// The tree level at which the public labels live (0 = leaves).
    pub predetermined_level: usize,
    /// Node labels at level `predetermined_level`, ordered left to right.
    pub node_labels: Vec<Hash>,
}

/// The proof store.
///
/// In-memory storage for the v1 implementation; the public surface is
/// designed so a persistent backend (file / RocksDB / KV) can be swapped in
/// without changing call sites. The store is the **availability** layer
/// only; verification always terminates at the on-chain BSV root, never at
/// the store.
#[derive(Debug)]
pub struct ProofStore {
    predetermined_level: usize,
    storage: HashMap<IndexKey, StoredProof>,
    assistance_by_root: HashMap<Hash, ProofAssistance>,
}

impl ProofStore {
    /// Create a new in-memory store with the given predetermined level for
    /// proof-assistance publication.
    #[must_use]
    pub fn new(predetermined_level: usize) -> Self {
        Self {
            predetermined_level,
            storage: HashMap::new(),
            assistance_by_root: HashMap::new(),
        }
    }

    /// Predetermined level `k` at which proof-assistance is published.
    #[must_use]
    pub fn predetermined_level(&self) -> usize {
        self.predetermined_level
    }

    /// Look up the public proof-assistance for a given anchored root.
    #[must_use]
    pub fn proof_assistance_for(&self, root: &Hash) -> Option<&ProofAssistance> {
        self.assistance_by_root.get(root)
    }

    /// Generate a Merkle proof for the leaf at `leaf_index`, shard it at the
    /// predetermined level, store it under `key`, compute the public
    /// proof-assistance for the resulting root, and return the root.
    ///
    /// The caller anchors the returned root on BSV (e.g. via an `OP_RETURN`
    /// data-carrier output) — that is the third data the patent's claim 1
    /// names as published on-chain.
    ///
    /// # Errors
    ///
    /// Propagates [`MerkleError::EmptyTree`] (via [`ProofStoreError::Merkle`])
    /// when `leaves` is empty, and [`MerkleError::IndexOutOfRange`] when
    /// `leaf_index >= leaves.len()`.
    pub fn anchor(
        &mut self,
        key: IndexKey,
        leaves: &[Hash],
        leaf_index: usize,
    ) -> Result<Hash, ProofStoreError> {
        let root = merkle_root(leaves)?;
        let proof = merkle_proof(leaves, leaf_index)?;

        let shards = shard_proof(&proof, self.predetermined_level);

        let stored = StoredProof {
            key: key.clone(),
            leaf_index,
            shards,
            expected_root: root,
        };

        self.storage.insert(key, stored);

        let assistance = compute_proof_assistance(leaves, self.predetermined_level)?;
        self.assistance_by_root.insert(root, assistance);

        Ok(root)
    }

    /// Look up the stored proof for an index key (WO 2025/119666 claim 12).
    ///
    /// # Errors
    ///
    /// Returns [`ProofStoreError::KeyNotFound`] if no proof was anchored under
    /// this exact key.
    pub fn query(&self, key: &IndexKey) -> Result<&StoredProof, ProofStoreError> {
        self.storage.get(key).ok_or(ProofStoreError::KeyNotFound)
    }

    /// Verify that `leaf` plus the stored proof under `key` reconstructs to
    /// the anchored root, using the requested mode.
    ///
    /// `Adversarial` mode reassembles all stored shards into the full Merkle
    /// proof and verifies against the anchored root — independent audit
    /// evidence.
    ///
    /// `TrustedOperational` mode is documented but not yet wired; it returns
    /// [`ProofStoreError::TrustedOperationalNotImplemented`] until the
    /// EC-compression primitives land in step 5+.
    ///
    /// # Errors
    ///
    /// - [`ProofStoreError::RootMismatch`] when the leaf + stored shards do
    ///   not reconstruct to the anchored root.
    /// - [`ProofStoreError::TrustedOperationalNotImplemented`] when `mode`
    ///   is [`ReconstructionMode::TrustedOperational`].
    pub fn verify(
        &self,
        leaf: &Hash,
        stored: &StoredProof,
        mode: ReconstructionMode,
    ) -> Result<(), ProofStoreError> {
        match mode {
            ReconstructionMode::Adversarial => {
                let reassembled = stored.reassemble();
                let reconstructed = reassembled.reconstruct_root(leaf);
                if reconstructed == stored.expected_root {
                    Ok(())
                } else {
                    Err(ProofStoreError::RootMismatch)
                }
            }
            ReconstructionMode::TrustedOperational => {
                Err(ProofStoreError::TrustedOperationalNotImplemented)
            }
        }
    }

    /// Verify against the public proof-assistance instead of reassembling all
    /// shards: the verifier walks the lower shards from leaf up to the
    /// predetermined level, checks that the resulting node matches the
    /// corresponding public label, and independently verifies that the
    /// public labels hash up to the anchored root.
    ///
    /// This is the patent's intended consumer flow for claim 8 — it lets a
    /// verifier complete verification using only the lower shard and the
    /// public on-chain data, never trusting the proofstore for the upper path.
    ///
    /// # Errors
    ///
    /// - [`ProofStoreError::KeyNotFound`] when no proof-assistance has been
    ///   anchored for `stored.expected_root`.
    /// - [`ProofStoreError::AssistanceMismatch`] when the lower shards do not
    ///   walk up to a label that matches the published level-`k` node, or
    ///   when the published labels do not themselves hash to the anchored root.
    pub fn verify_with_assistance(
        &self,
        leaf: &Hash,
        stored: &StoredProof,
    ) -> Result<(), ProofStoreError> {
        let assistance = self
            .proof_assistance_for(&stored.expected_root)
            .ok_or(ProofStoreError::KeyNotFound)?;

        // The lower shard is the one whose from_level == 0.
        let lower_siblings: &[Hash] = stored
            .shards
            .iter()
            .find(|s| s.from_level == 0)
            .map_or(&[][..], |s| s.siblings.as_slice());

        let k = assistance.predetermined_level;

        // Walk from the leaf up to level k using only the lower siblings.
        let mut current = *leaf;
        let mut idx = stored.leaf_index;
        for sibling in lower_siblings.iter().take(k) {
            current = if idx & 1 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            idx >>= 1;
        }

        // After walking k levels, `idx` is the index of the level-k node we
        // should match against the published labels.
        if idx >= assistance.node_labels.len() {
            return Err(ProofStoreError::AssistanceMismatch);
        }
        if assistance.node_labels[idx] != current {
            return Err(ProofStoreError::AssistanceMismatch);
        }

        // Independently verify the public labels hash up to the anchored
        // root. (If the published level-k labels are forged, this would
        // fail unless the on-chain root is also corrupted, which we treat
        // as outside the threat model.)
        let labels_root = merkle_root(&assistance.node_labels)?;
        if labels_root != stored.expected_root {
            return Err(ProofStoreError::AssistanceMismatch);
        }

        Ok(())
    }
}

/// Split a Merkle proof at the predetermined level into non-overlapping
/// shards. Returns one shard for the levels below `k` and one for the levels
/// `[k, depth)`. Empty shards are omitted, so a proof shorter than `k+1`
/// levels yields a single shard.
fn shard_proof(proof: &MerkleProof, predetermined_level: usize) -> Vec<ProofShard> {
    let depth = proof.siblings.len();
    if depth == 0 {
        return Vec::new();
    }
    let k = predetermined_level.min(depth);
    let mut shards = Vec::new();
    if k > 0 {
        shards.push(ProofShard {
            from_level: 0,
            to_level: k,
            siblings: proof.siblings[..k].to_vec(),
        });
    }
    if k < depth {
        shards.push(ProofShard {
            from_level: k,
            to_level: depth,
            siblings: proof.siblings[k..].to_vec(),
        });
    }
    shards
}

/// Compute the node labels at level `target_level` of the BSV Merkle tree
/// over `leaves`. If the tree is shallower than `target_level`, the assistance
/// degrades to the labels at the deepest level (the root).
fn compute_proof_assistance(
    leaves: &[Hash],
    target_level: usize,
) -> Result<ProofAssistance, ProofStoreError> {
    if leaves.is_empty() {
        return Err(ProofStoreError::Merkle(MerkleError::EmptyTree));
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut current_level = 0usize;
    while current_level < target_level && level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next: Vec<Hash> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
        current_level += 1;
    }
    Ok(ProofAssistance {
        predetermined_level: current_level,
        node_labels: level,
    })
}

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

    fn key(txid_byte: u8, block_position: u32) -> IndexKey {
        let mut txid = [0u8; 32];
        txid[31] = txid_byte;
        IndexKey {
            txid,
            direction: Direction::Output,
            position: 0,
            block_position,
            locking_script: None,
            unlocking_script: None,
            amount: None,
        }
    }

    // ------------------------------------------------------------------
    // Anchor + query + verify (the happy path, both modes the v1 supports)
    // ------------------------------------------------------------------

    #[test]
    fn anchor_then_query_and_verify_assembled_round_trips() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        let root = store.anchor(key(1, 3), &l, 3).unwrap();
        assert_eq!(root, merkle_root(&l).unwrap());

        let stored = store.query(&key(1, 3)).unwrap();
        store
            .verify(&l[3], stored, ReconstructionMode::Adversarial)
            .unwrap();
    }

    #[test]
    fn verify_with_assistance_round_trips() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 3), &l, 3).unwrap();
        let stored = store.query(&key(1, 3)).unwrap();
        store.verify_with_assistance(&l[3], stored).unwrap();
    }

    #[test]
    fn assistance_labels_hash_back_to_anchored_root() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        let root = store.anchor(key(1, 0), &l, 0).unwrap();
        let assistance = store.proof_assistance_for(&root).unwrap();
        let labels_root = merkle_root(&assistance.node_labels).unwrap();
        assert_eq!(labels_root, root);
    }

    // ------------------------------------------------------------------
    // Sharding properties (claims 2–3)
    // ------------------------------------------------------------------

    #[test]
    fn shards_are_non_overlapping_and_cover_the_full_proof() {
        let l = leaves(16);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 5), &l, 5).unwrap();
        let stored = store.query(&key(1, 5)).unwrap();

        // Adjacent shards must abut (no gap, no overlap), and together they
        // must equal the full proof generated directly by the merkle layer.
        for window in stored.shards.windows(2) {
            assert_eq!(window[0].to_level, window[1].from_level);
        }
        let reassembled = stored.reassemble();
        let direct = merkle_proof(&l, 5).unwrap();
        assert_eq!(reassembled, direct);
    }

    #[test]
    fn single_leaf_yields_no_shards() {
        let l = leaves(1);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 0), &l, 0).unwrap();
        let stored = store.query(&key(1, 0)).unwrap();
        assert!(stored.shards.is_empty());
        // And reconstruction still succeeds (single-leaf root == leaf).
        store
            .verify(&l[0], stored, ReconstructionMode::Adversarial)
            .unwrap();
    }

    #[test]
    fn predetermined_level_clamps_to_proof_depth() {
        // 4 leaves → proof depth 2. predetermined_level = 10 is clamped to 2,
        // so the upper shard is empty and only one shard (levels 0..2) is stored.
        let l = leaves(4);
        let mut store = ProofStore::new(10);
        store.anchor(key(1, 1), &l, 1).unwrap();
        let stored = store.query(&key(1, 1)).unwrap();
        assert_eq!(stored.shards.len(), 1);
        assert_eq!(stored.shards[0].from_level, 0);
        assert_eq!(stored.shards[0].to_level, 2);
    }

    // ------------------------------------------------------------------
    // Adversarial negatives
    // ------------------------------------------------------------------

    #[test]
    fn verify_rejects_wrong_leaf() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 4), &l, 4).unwrap();
        let stored = store.query(&key(1, 4)).unwrap();
        let mut wrong = l[4];
        wrong[0] ^= 1;
        let err = store
            .verify(&wrong, stored, ReconstructionMode::Adversarial)
            .unwrap_err();
        assert!(matches!(err, ProofStoreError::RootMismatch));
    }

    #[test]
    fn verify_rejects_tampered_shard() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 4), &l, 4).unwrap();
        let mut stored = store.query(&key(1, 4)).unwrap().clone();
        // Tamper a sibling inside the lower shard.
        stored.shards[0].siblings[0][0] ^= 1;
        let err = store
            .verify(&l[4], &stored, ReconstructionMode::Adversarial)
            .unwrap_err();
        assert!(matches!(err, ProofStoreError::RootMismatch));
    }

    #[test]
    fn query_unknown_key_returns_key_not_found() {
        let store = ProofStore::new(2);
        let err = store.query(&key(99, 99)).unwrap_err();
        assert!(matches!(err, ProofStoreError::KeyNotFound));
    }

    #[test]
    fn trusted_operational_mode_is_not_implemented_in_v1() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 0), &l, 0).unwrap();
        let stored = store.query(&key(1, 0)).unwrap();
        let err = store
            .verify(&l[0], stored, ReconstructionMode::TrustedOperational)
            .unwrap_err();
        assert!(matches!(
            err,
            ProofStoreError::TrustedOperationalNotImplemented
        ));
    }

    // ------------------------------------------------------------------
    // Proof-assistance negatives (claim 8 path)
    // ------------------------------------------------------------------

    #[test]
    fn verify_with_assistance_rejects_wrong_leaf() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);
        store.anchor(key(1, 6), &l, 6).unwrap();
        let stored = store.query(&key(1, 6)).unwrap();
        let mut wrong = l[6];
        wrong[0] ^= 1;
        let err = store.verify_with_assistance(&wrong, stored).unwrap_err();
        assert!(matches!(err, ProofStoreError::AssistanceMismatch));
    }

    // ------------------------------------------------------------------
    // Index schema: distinct keys store distinct proofs
    // ------------------------------------------------------------------

    #[test]
    fn distinct_index_keys_store_distinct_proofs() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);

        // Same txid + position but different direction → distinct keys.
        let k1 = IndexKey {
            direction: Direction::Output,
            ..key(7, 2)
        };
        let k2 = IndexKey {
            direction: Direction::Input,
            ..key(7, 2)
        };

        store.anchor(k1.clone(), &l, 2).unwrap();
        store.anchor(k2.clone(), &l, 5).unwrap();

        assert_eq!(store.query(&k1).unwrap().leaf_index, 2);
        assert_eq!(store.query(&k2).unwrap().leaf_index, 5);
    }

    #[test]
    fn locking_script_distinguishes_keys() {
        let l = leaves(8);
        let mut store = ProofStore::new(2);

        let mut k1 = key(1, 0);
        k1.locking_script = Some(vec![0x76, 0xa9]);
        let mut k2 = key(1, 0);
        k2.locking_script = Some(vec![0x00, 0x6a]);

        store.anchor(k1.clone(), &l, 0).unwrap();
        store.anchor(k2.clone(), &l, 7).unwrap();

        assert_eq!(store.query(&k1).unwrap().leaf_index, 0);
        assert_eq!(store.query(&k2).unwrap().leaf_index, 7);
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
            prop::collection::vec(arb_hash(), 1..40).prop_flat_map(|v| {
                let len = v.len();
                (Just(v), 0..len)
            })
        }

        fn arb_key(seed: u8) -> IndexKey {
            let mut txid = [0u8; 32];
            txid[0] = seed;
            IndexKey {
                txid,
                direction: if seed & 1 == 0 {
                    Direction::Output
                } else {
                    Direction::Input
                },
                position: u32::from(seed),
                block_position: u32::from(seed) * 7,
                locking_script: None,
                unlocking_script: None,
                amount: None,
            }
        }

        proptest! {
            #[test]
            fn anchor_query_verify_round_trips(
                (leaves, index) in arb_leaves_and_index(),
                level in 0usize..6,
                seed in any::<u8>(),
            ) {
                let mut store = ProofStore::new(level);
                let key = arb_key(seed);
                let root = store.anchor(key.clone(), &leaves, index).unwrap();
                prop_assert_eq!(root, merkle_root(&leaves).unwrap());

                let stored = store.query(&key).unwrap();
                prop_assert_eq!(stored.leaf_index, index);
                prop_assert_eq!(stored.expected_root, root);
                store
                    .verify(&leaves[index], stored, ReconstructionMode::Adversarial)
                    .unwrap();
            }

            #[test]
            fn shards_concatenate_to_the_full_proof(
                (leaves, index) in arb_leaves_and_index(),
                level in 0usize..6,
                seed in any::<u8>(),
            ) {
                let mut store = ProofStore::new(level);
                let key = arb_key(seed);
                store.anchor(key.clone(), &leaves, index).unwrap();
                let stored = store.query(&key).unwrap();

                // Shards must be ordered and adjacent.
                for w in stored.shards.windows(2) {
                    prop_assert_eq!(w[0].to_level, w[1].from_level);
                }
                // Reassembly must equal the direct proof.
                let direct = merkle_proof(&leaves, index).unwrap();
                prop_assert_eq!(stored.reassemble(), direct);
            }

            #[test]
            fn tampered_shard_fails_verification(
                (leaves, index) in arb_leaves_and_index(),
                seed in any::<u8>(),
            ) {
                prop_assume!(leaves.len() > 1);
                let mut store = ProofStore::new(1);
                let key = arb_key(seed);
                store.anchor(key.clone(), &leaves, index).unwrap();
                let mut stored = store.query(&key).unwrap().clone();
                prop_assume!(!stored.shards.is_empty() && !stored.shards[0].siblings.is_empty());
                stored.shards[0].siblings[0][0] ^= 1;
                prop_assert!(store
                    .verify(&leaves[index], &stored, ReconstructionMode::Adversarial)
                    .is_err());
            }

            #[test]
            fn assistance_labels_hash_to_anchored_root_for_random_trees(
                leaves in prop::collection::vec(arb_hash(), 1..40),
                level in 0usize..6,
                seed in any::<u8>(),
            ) {
                let mut store = ProofStore::new(level);
                let key = arb_key(seed);
                let root = store.anchor(key, &leaves, 0).unwrap();
                let assistance = store.proof_assistance_for(&root).unwrap();
                let labels_root = merkle_root(&assistance.node_labels).unwrap();
                prop_assert_eq!(labels_root, root);
            }
        }
    }
}
