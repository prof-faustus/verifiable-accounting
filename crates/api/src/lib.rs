// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Verifier-facing query/retrieval API.
//!
//! Composes the lower layers into a single audit verification call:
//!
//! ```text
//! query → presence (merkle inclusion against BSV-anchored root)
//!       → retrieval (selective disclosure via proofstore)
//!       → arithmetic (recomputation over disclosed records, accounting layer)
//!       → result
//! ```
//!
//! Verification always terminates in a BSV block-header Merkle root via the
//! `merkle` layer. The proof store is queried only for availability of
//! evidence, never as a trust anchor.
//!
//! The audit API rejects results produced via
//! `ReconstructionMode::TrustedOperational`: only adversarially-sound
//! Merkle reconstruction is accepted as audit evidence.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use vaa_merkle::Hash;
use vaa_proofstore::{IndexKey, ProofStore, ProofStoreError, ReconstructionMode};

/// Errors returned by the API layer.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The proofstore did not contain a proof for the supplied index key, or
    /// the stored proof failed to reconstruct.
    #[error("proofstore: {0}")]
    ProofStore(#[from] ProofStoreError),
    /// The disclosed record bytes did not hash to the leaf claimed by the proof.
    #[error("disclosed record does not hash to the proven leaf")]
    RecordLeafMismatch,
    /// The verification was requested in a non-adversarial mode. The audit
    /// API rejects this by design: only adversarial reconstruction yields
    /// independent audit evidence.
    #[error("audit API rejects non-adversarial reconstruction mode")]
    NonAdversarialMode,
}

/// A self-contained audit bundle presented to the verifier.
///
/// The disclosed record is the raw bytes anchored as the leaf; the verifier
/// hashes the record to derive the leaf and then proves inclusion via the
/// stored Merkle proof against the BSV-anchored root.
#[derive(Clone, Debug)]
pub struct AuditBundle {
    /// Index key under which the Merkle proof is stored.
    pub index_key: IndexKey,
    /// The disclosed record bytes — exactly what was anchored as the leaf.
    pub disclosed_record: Vec<u8>,
    /// The leaf the proof witnesses inclusion of; must equal
    /// `vaa_bsv::hash::double_sha256(&disclosed_record)`.
    pub leaf: Hash,
    /// Reconstruction mode the verifier should use. Must be `Adversarial`.
    pub mode: ReconstructionMode,
}

/// What an audit verification produces on success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvidence {
    /// The BSV-anchored Merkle root the inclusion was proved against.
    pub merkle_root: Hash,
    /// The leaf index within the anchored tree.
    pub leaf_index: usize,
    /// The disclosed record (returned for the caller's audit trail).
    pub disclosed_record: Vec<u8>,
}

/// The verifier-facing composition layer.
#[derive(Debug)]
pub struct AuditVerifier<'a> {
    /// The proofstore the verifier queries for stored evidence.
    pub store: &'a ProofStore,
}

impl<'a> AuditVerifier<'a> {
    /// Construct a verifier bound to a proofstore.
    #[must_use]
    pub fn new(store: &'a ProofStore) -> Self {
        Self { store }
    }

    /// Run the full audit verification flow for one bundle.
    ///
    /// 1. Reject any non-adversarial mode at the API surface.
    /// 2. Hash the disclosed record and confirm it equals the bundle's leaf.
    /// 3. Query the proofstore for the stored Merkle proof.
    /// 4. Reconstruct the Merkle root from the leaf and the stored shards
    ///    in adversarial mode.
    ///
    /// # Errors
    ///
    /// - [`ApiError::NonAdversarialMode`] when `bundle.mode != Adversarial`.
    /// - [`ApiError::RecordLeafMismatch`] when the disclosed record does
    ///   not hash to the claimed leaf.
    /// - [`ApiError::ProofStore`] when the index key is missing or the
    ///   stored proof does not reconstruct.
    pub fn verify(&self, bundle: &AuditBundle) -> Result<AuditEvidence, ApiError> {
        if bundle.mode != ReconstructionMode::Adversarial {
            return Err(ApiError::NonAdversarialMode);
        }

        let recomputed_leaf = vaa_bsv::hash::double_sha256(&bundle.disclosed_record);
        if recomputed_leaf != bundle.leaf {
            return Err(ApiError::RecordLeafMismatch);
        }

        let stored = self.store.query(&bundle.index_key)?;
        self.store
            .verify(&bundle.leaf, stored, ReconstructionMode::Adversarial)?;

        Ok(AuditEvidence {
            merkle_root: stored.expected_root,
            leaf_index: stored.leaf_index,
            disclosed_record: bundle.disclosed_record.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaa_bsv::hash::double_sha256;
    use vaa_merkle::merkle_root;
    use vaa_proofstore::Direction;

    fn record(i: u8) -> Vec<u8> {
        format!("record-{i:03}").into_bytes()
    }

    fn leaves_for(records: &[Vec<u8>]) -> Vec<Hash> {
        records.iter().map(|r| double_sha256(r)).collect()
    }

    fn key(seed: u8, block_position: u32, leaf: &Hash) -> IndexKey {
        IndexKey {
            txid: *leaf,
            direction: Direction::Output,
            position: u32::from(seed),
            block_position,
            locking_script: None,
            unlocking_script: None,
            amount: None,
        }
    }

    #[test]
    fn happy_path_verifies_a_disclosed_record() {
        let records: Vec<Vec<u8>> = (0..8u8).map(record).collect();
        let leaves = leaves_for(&records);
        let mut store = ProofStore::new(1);
        let idx = 3usize;
        let k = key(idx as u8, idx as u32, &leaves[idx]);
        let root = store.anchor(k.clone(), &leaves, idx).unwrap();
        assert_eq!(root, merkle_root(&leaves).unwrap());

        let bundle = AuditBundle {
            index_key: k,
            disclosed_record: records[idx].clone(),
            leaf: leaves[idx],
            mode: ReconstructionMode::Adversarial,
        };

        let ev = AuditVerifier::new(&store).verify(&bundle).unwrap();
        assert_eq!(ev.merkle_root, root);
        assert_eq!(ev.leaf_index, idx);
        assert_eq!(ev.disclosed_record, records[idx]);
    }

    #[test]
    fn rejects_non_adversarial_mode() {
        let records: Vec<Vec<u8>> = (0..4u8).map(record).collect();
        let leaves = leaves_for(&records);
        let mut store = ProofStore::new(1);
        let k = key(0, 0, &leaves[0]);
        store.anchor(k.clone(), &leaves, 0).unwrap();
        let bundle = AuditBundle {
            index_key: k,
            disclosed_record: records[0].clone(),
            leaf: leaves[0],
            mode: ReconstructionMode::TrustedOperational,
        };
        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::NonAdversarialMode));
    }

    #[test]
    fn rejects_disclosed_record_that_does_not_hash_to_leaf() {
        let records: Vec<Vec<u8>> = (0..4u8).map(record).collect();
        let leaves = leaves_for(&records);
        let mut store = ProofStore::new(1);
        let k = key(0, 0, &leaves[0]);
        store.anchor(k.clone(), &leaves, 0).unwrap();
        let bundle = AuditBundle {
            index_key: k,
            disclosed_record: b"WRONG-RECORD".to_vec(),
            leaf: leaves[0],
            mode: ReconstructionMode::Adversarial,
        };
        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::RecordLeafMismatch));
    }

    #[test]
    fn rejects_unknown_index_key() {
        let records: Vec<Vec<u8>> = (0..4u8).map(record).collect();
        let leaves = leaves_for(&records);
        let store = ProofStore::new(1);
        let k = key(99, 99, &leaves[0]);
        let bundle = AuditBundle {
            index_key: k,
            disclosed_record: records[0].clone(),
            leaf: leaves[0],
            mode: ReconstructionMode::Adversarial,
        };
        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(
            err,
            ApiError::ProofStore(ProofStoreError::KeyNotFound)
        ));
    }

    #[test]
    fn rejects_wrong_leaf_for_known_key() {
        let records: Vec<Vec<u8>> = (0..8u8).map(record).collect();
        let leaves = leaves_for(&records);
        let mut store = ProofStore::new(1);
        let k = key(0, 2, &leaves[2]);
        store.anchor(k.clone(), &leaves, 2).unwrap();
        let bundle = AuditBundle {
            index_key: k,
            disclosed_record: records[4].clone(),
            leaf: leaves[2],
            mode: ReconstructionMode::Adversarial,
        };
        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::RecordLeafMismatch));
    }
}
