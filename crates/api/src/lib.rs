// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Verifier-facing query/retrieval API.
//!
//! Composes the lower layers into a single audit verification flow:
//!
//! ```text
//! query → presence (merkle) → retrieval (proofstore)
//!       → arithmetic (zk + accounting) → range (zk)
//!       → selective opening → result + residual assertions
//! ```
//!
//! Verification always terminates in a BSV block-header Merkle root via the
//! `merkle` layer. The proof store is queried only for availability of
//! evidence, never as a trust anchor.
//!
//! The API rejects results obtained via `ReconstructionMode::TrustedOperational`:
//! only adversarially-sound mode is accepted as audit evidence.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use std::ops::Range;

use vaa_commit::{Blinding, CommitError, Commitment};
use vaa_merkle::Hash;
use vaa_proofstore::{IndexKey, ProofStore, ProofStoreError, ReconstructionMode};
use vaa_zk::{RangeProof, ZkError};

/// Errors returned by the API layer.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The proofstore did not contain a proof for the supplied index key, or
    /// the stored proof failed to reconstruct.
    #[error("proofstore: {0}")]
    ProofStore(#[from] ProofStoreError),
    /// The Pedersen commitment did not open to the disclosed value under the
    /// supplied blinding.
    #[error("commitment did not open to the disclosed value")]
    OpeningFailed,
    /// A range proof was supplied but did not verify against the commitment.
    #[error("range proof did not verify: {0}")]
    RangeProofFailed(#[from] ZkError),
    /// A commitment-layer error (invalid encoding, invalid blinding, etc.).
    #[error("commit: {0}")]
    Commit(#[from] CommitError),
    /// The verification was requested in a non-adversarial mode. The audit
    /// API rejects this by design: only `ReconstructionMode::Adversarial`
    /// yields independent audit evidence.
    #[error("audit API rejects non-adversarial reconstruction mode")]
    NonAdversarialMode,
}

/// A self-contained audit bundle presented to the verifier.
///
/// Carries everything needed to verify a single accounting claim against an
/// on-chain anchor: where to look the proof up, the leaf inclusion proof
/// (via the index key), the commitment + opening to disclose, and optionally
/// a range proof to bound the disclosed value.
#[derive(Clone, Debug)]
pub struct AuditBundle {
    /// Index key under which the merkle proof is stored.
    pub index_key: IndexKey,
    /// The leaf that the proof witnesses inclusion of.
    pub leaf: Hash,
    /// The Pedersen commitment to verify the opening of.
    pub commitment: Commitment,
    /// The disclosed accounting value.
    pub disclosed_value: u64,
    /// The blinding the commitment was made under.
    pub blinding: Blinding,
    /// Optional Bulletproof range proof asserting the disclosed value is
    /// within `[min_value, 2^min_bits)` for the prover-chosen bound.
    pub range_proof: Option<RangeProof>,
    /// Reconstruction mode the verifier should use. Must be `Adversarial` for
    /// the audit API; `TrustedOperational` is rejected.
    pub mode: ReconstructionMode,
}

/// What an audit verification produces on success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvidence {
    /// The merkle root the inclusion was proved against.
    pub merkle_root: Hash,
    /// The leaf index within the anchored tree.
    pub leaf_index: usize,
    /// 33-byte serialised Pedersen commitment.
    pub commitment_bytes: [u8; 33],
    /// The disclosed value (cleartext on the audit-evidence side).
    pub disclosed_value: u64,
    /// If a range proof was checked, the certified range.
    pub range_certified: Option<Range<u64>>,
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
    /// Order of operations matters: each step is short-circuited so a
    /// failure at any layer surfaces immediately and structurally.
    ///
    /// 1. Reject any non-adversarial mode (the audit surface accepts only
    ///    adversarially-sound reconstruction; see `SECURITY.md`).
    /// 2. Query the proofstore for the stored Merkle proof.
    /// 3. Reconstruct the Merkle root from the supplied leaf and the stored
    ///    shards in adversarial mode.
    /// 4. Verify the Pedersen commitment opens to `(disclosed_value, blinding)`.
    /// 5. If a range proof is present, verify it against the commitment.
    ///
    /// # Errors
    ///
    /// - [`ApiError::NonAdversarialMode`] when `bundle.mode != Adversarial`.
    /// - [`ApiError::ProofStore`] when the index key is missing or the
    ///   stored proof does not reconstruct.
    /// - [`ApiError::OpeningFailed`] when the commitment does not open.
    /// - [`ApiError::RangeProofFailed`] when a range proof is supplied and
    ///   does not verify.
    pub fn verify(&self, bundle: &AuditBundle) -> Result<AuditEvidence, ApiError> {
        // 1. Reject any non-adversarial mode at the API surface.
        if bundle.mode != ReconstructionMode::Adversarial {
            return Err(ApiError::NonAdversarialMode);
        }

        // 2 + 3. Query and adversarial-reconstruct.
        let stored = self.store.query(&bundle.index_key)?;
        self.store
            .verify(&bundle.leaf, stored, ReconstructionMode::Adversarial)?;

        // 4. Pedersen opening check.
        if !bundle
            .commitment
            .verify_open(bundle.disclosed_value, &bundle.blinding)
        {
            return Err(ApiError::OpeningFailed);
        }

        // 5. Optional range proof.
        let range_certified = match &bundle.range_proof {
            Some(rp) => Some(rp.verify(&bundle.commitment)?),
            None => None,
        };

        Ok(AuditEvidence {
            merkle_root: stored.expected_root,
            leaf_index: stored.leaf_index,
            commitment_bytes: bundle.commitment.serialize(),
            disclosed_value: bundle.disclosed_value,
            range_certified,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use vaa_merkle::merkle_root;
    use vaa_proofstore::Direction;

    fn leaves(n: u8) -> Vec<Hash> {
        (1..=n)
            .map(|i| {
                let mut h = [0u8; 32];
                h[31] = i;
                h
            })
            .collect()
    }

    fn key(seed: u8, block_position: u32) -> IndexKey {
        let mut txid = [0u8; 32];
        txid[31] = seed;
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

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(20_260_530)
    }

    fn anchored(store: &mut ProofStore, l: &[Hash], idx: usize) -> (IndexKey, Hash) {
        let block_pos = u32::try_from(idx).expect("test index fits in u32");
        let k = key(idx as u8, block_pos);
        let root = store.anchor(k.clone(), l, idx).unwrap();
        (k, root)
    }

    #[test]
    fn happy_path_verifies_without_range_proof() {
        let l = leaves(8);
        let mut store = ProofStore::new(1);
        let (k, root) = anchored(&mut store, &l, 3);
        assert_eq!(root, merkle_root(&l).unwrap());

        let blinding = Blinding::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(100_000, &blinding);

        let bundle = AuditBundle {
            index_key: k,
            leaf: l[3],
            commitment,
            disclosed_value: 100_000,
            blinding,
            range_proof: None,
            mode: ReconstructionMode::Adversarial,
        };

        let v = AuditVerifier::new(&store);
        let ev = v.verify(&bundle).unwrap();
        assert_eq!(ev.merkle_root, root);
        assert_eq!(ev.leaf_index, 3);
        assert_eq!(ev.disclosed_value, 100_000);
        assert!(ev.range_certified.is_none());
    }

    #[test]
    fn happy_path_with_range_proof() {
        let l = leaves(8);
        let mut store = ProofStore::new(1);
        let (k, _) = anchored(&mut store, &l, 5);

        let blinding = Blinding::from_bytes([0xa5; 32]).unwrap();
        let value = 42_000_u64;
        let commitment = Commitment::commit(value, &blinding);
        let rp = RangeProof::prove(value, &blinding, 0, 32, &mut rng()).unwrap();

        let bundle = AuditBundle {
            index_key: k,
            leaf: l[5],
            commitment,
            disclosed_value: value,
            blinding,
            range_proof: Some(rp),
            mode: ReconstructionMode::Adversarial,
        };

        let ev = AuditVerifier::new(&store).verify(&bundle).unwrap();
        let cert = ev.range_certified.expect("range was checked");
        assert!(cert.contains(&value));
    }

    #[test]
    fn rejects_non_adversarial_mode() {
        let l = leaves(4);
        let mut store = ProofStore::new(1);
        let (k, _) = anchored(&mut store, &l, 0);
        let blinding = Blinding::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(1, &blinding);

        let bundle = AuditBundle {
            index_key: k,
            leaf: l[0],
            commitment,
            disclosed_value: 1,
            blinding,
            range_proof: None,
            mode: ReconstructionMode::TrustedOperational,
        };

        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::NonAdversarialMode));
    }

    #[test]
    fn rejects_unknown_index_key() {
        let l = leaves(4);
        let store = ProofStore::new(1);
        let blinding = Blinding::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(1, &blinding);

        let bundle = AuditBundle {
            index_key: key(99, 99),
            leaf: l[0],
            commitment,
            disclosed_value: 1,
            blinding,
            range_proof: None,
            mode: ReconstructionMode::Adversarial,
        };

        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(
            err,
            ApiError::ProofStore(ProofStoreError::KeyNotFound)
        ));
    }

    #[test]
    fn rejects_wrong_leaf() {
        let l = leaves(8);
        let mut store = ProofStore::new(1);
        let (k, _) = anchored(&mut store, &l, 2);
        let blinding = Blinding::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(1, &blinding);
        let mut wrong = l[2];
        wrong[0] ^= 1;

        let bundle = AuditBundle {
            index_key: k,
            leaf: wrong,
            commitment,
            disclosed_value: 1,
            blinding,
            range_proof: None,
            mode: ReconstructionMode::Adversarial,
        };

        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(
            err,
            ApiError::ProofStore(ProofStoreError::RootMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_disclosed_value() {
        let l = leaves(8);
        let mut store = ProofStore::new(1);
        let (k, _) = anchored(&mut store, &l, 2);

        let blinding = Blinding::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(100_000, &blinding);

        let bundle = AuditBundle {
            index_key: k,
            leaf: l[2],
            commitment,
            disclosed_value: 99_999, // wrong
            blinding,
            range_proof: None,
            mode: ReconstructionMode::Adversarial,
        };

        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::OpeningFailed));
    }

    #[test]
    fn rejects_range_proof_for_wrong_commitment() {
        let l = leaves(8);
        let mut store = ProofStore::new(1);
        let (k, _) = anchored(&mut store, &l, 1);

        let r1 = Blinding::from_bytes([7u8; 32]).unwrap();
        let r2 = Blinding::from_bytes([8u8; 32]).unwrap();
        let value = 9_999_u64;
        let commitment = Commitment::commit(value, &r2); // bundle's commitment uses r2
        let rp = RangeProof::prove(value, &r1, 0, 32, &mut rng()).unwrap(); // proof made under r1

        let bundle = AuditBundle {
            index_key: k,
            leaf: l[1],
            commitment,
            disclosed_value: value,
            blinding: r2,
            range_proof: Some(rp),
            mode: ReconstructionMode::Adversarial,
        };

        let err = AuditVerifier::new(&store).verify(&bundle).unwrap_err();
        assert!(matches!(err, ApiError::RangeProofFailed(_)));
    }
}
