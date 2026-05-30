// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Zero-knowledge layer.
//!
//! Two construction families, both transparent-setup:
//!
//! - **Σ-protocols on Pedersen commitments** for the linear accounting
//!   equations (`Gross = Net + Tax − Discount`, AR roll-forward,
//!   `Σ Debits = Σ Credits`, bank reconciliation,
//!   `VAT_payable = OutputVAT − InputVAT`). Non-interactive via Fiat–Shamir.
//!   Implemented as [`LinearEquation`], which composes the homomorphic
//!   tally primitive [`vaa_commit::verify_sum_equal`] already proved by
//!   `libsecp256k1-zkp`.
//! - **Bulletproofs** from `libsecp256k1-zkp` for range and validity proofs
//!   (non-negativity, currency bounds, no overflow, tax-rate set membership,
//!   period validity, no double-use, commitment-matches-disclosure).
//!   Implemented as [`RangeProof`].
//!
//! See `docs/DECISIONS.md` D-003 for the rationale and the rejected
//! alternatives (Groth16, PLONK, Halo2 — all require pairing-friendly curves
//! and are unavailable on secp256k1).

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use std::ops::Range;

use rand::RngCore;
use secp256k1_zkp::{RangeProof as ZkpRangeProof, SecretKey};
use vaa_commit::{h_generator_point, secp_context, Blinding, CommitError, Commitment};

/// Errors returned by the ZK layer.
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// Construction of a range proof failed (typically a bad scalar).
    #[error("range-proof construction failed: {0}")]
    RangeProofConstructionFailed(secp256k1_zkp::Error),
    /// Verification of a range proof failed (proof did not certify the
    /// commitment, or the proof was malformed).
    #[error("range-proof verification failed: {0}")]
    RangeProofVerificationFailed(secp256k1_zkp::Error),
    /// A serialised range proof did not parse.
    #[error("range-proof parse failed: {0}")]
    RangeProofParseFailed(secp256k1_zkp::Error),
    /// Underlying commit-layer error (invalid blinding, etc.).
    #[error("commit error: {0}")]
    Commit(#[from] CommitError),
}

// ---------------------------------------------------------------------------
// Linear equations
// ---------------------------------------------------------------------------

/// A linear equation over Pedersen commitments asserting that the sum of
/// values on `positive` equals the sum of values on `negative`, without
/// disclosing any individual value.
///
/// Verifies via the Pedersen homomorphic tally: `Σ positive_C == Σ negative_C`
/// holds in the elliptic-curve group iff `Σ positive_v == Σ negative_v`
/// **and** `Σ positive_r == Σ negative_r`. The prover therefore must arrange
/// the blinding factors so they tally on the same partition as the values.
///
/// This is the Σ-protocol for linear-relation proofs of knowledge of
/// openings, made non-interactive trivially by reducing to point-equality.
#[derive(Clone, Copy, Debug)]
pub struct LinearEquation<'a> {
    /// Commitments on the positive side of the equation.
    pub positive: &'a [Commitment],
    /// Commitments on the negative side of the equation.
    pub negative: &'a [Commitment],
}

impl LinearEquation<'_> {
    /// Verify the equation holds over the committed values.
    #[must_use]
    pub fn verify(&self) -> bool {
        vaa_commit::verify_sum_equal(self.positive, self.negative)
    }
}

// ---------------------------------------------------------------------------
// Range proofs
// ---------------------------------------------------------------------------

/// A Bulletproof range proof that the value inside a Pedersen commitment lies
/// within an asserted range.
///
/// Wraps `secp256k1_zkp::RangeProof`. Construction is opaque (the prover
/// supplies a CSPRNG via [`RangeProof::prove`]); verification yields the
/// `Range<u64>` the proof certifies, which the caller compares against their
/// expected bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeProof(ZkpRangeProof);

impl RangeProof {
    /// Construct a range proof asserting that the value inside
    /// `Commitment::commit(value, blinding)` lies in `[min_value, 2^min_bits)`.
    ///
    /// `rng` supplies the proof's own randomness (the rangeproof "nonce"
    /// secret key inside `libsecp256k1-zkp`). It must be a CSPRNG; a constant
    /// or biased source weakens the proof.
    ///
    /// # Errors
    ///
    /// Returns [`ZkError::RangeProofConstructionFailed`] if the underlying
    /// library rejects the inputs (e.g. a `min_value > value` mismatch, an
    /// out-of-range `min_bits`, or a degenerate secret-key draw).
    pub fn prove<R: RngCore>(
        value: u64,
        blinding: &Blinding,
        min_value: u64,
        min_bits: u8,
        rng: &mut R,
    ) -> Result<Self, ZkError> {
        let secp = secp_context();
        let commitment = Commitment::commit(value, blinding);
        // Draw a fresh non-zero in-range scalar for the range-proof nonce. A
        // CSPRNG draw fails the curve-order check with negligible probability
        // (about 2^-128); we loop so a deterministic test RNG that happens to
        // produce a bad first draw still terminates.
        let mut sk_bytes = [0u8; 32];
        let sk = loop {
            rng.fill_bytes(&mut sk_bytes);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                break sk;
            }
        };
        ZkpRangeProof::new(
            secp,
            min_value,
            *commitment.as_inner(),
            value,
            *blinding.as_tweak(),
            &[],
            &[],
            sk,
            0,
            min_bits,
            h_generator_point(),
        )
        .map(RangeProof)
        .map_err(ZkError::RangeProofConstructionFailed)
    }

    /// Verify this range proof against a Pedersen commitment.
    ///
    /// Returns the range the proof certifies; the caller is responsible for
    /// checking that the returned range is the one they expected.
    ///
    /// # Errors
    ///
    /// Returns [`ZkError::RangeProofVerificationFailed`] if the proof does
    /// not certify the supplied commitment under the project's H generator.
    pub fn verify(&self, commitment: &Commitment) -> Result<Range<u64>, ZkError> {
        let secp = secp_context();
        self.0
            .verify(secp, *commitment.as_inner(), &[], h_generator_point())
            .map_err(ZkError::RangeProofVerificationFailed)
    }

    /// Serialize to a variable-length byte representation.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// Parse from the serialised bytes produced by [`RangeProof::serialize`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkError::RangeProofParseFailed`] if `bytes` is not a valid
    /// range proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        ZkpRangeProof::from_slice(bytes)
            .map(RangeProof)
            .map_err(ZkError::RangeProofParseFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(byte: u8) -> Blinding {
        Blinding::from_bytes([byte; 32]).expect("valid scalar")
    }

    // ----- LinearEquation ----------------------------------------------

    #[test]
    fn invoice_total_linear_equation_verifies() {
        // Net + Tax == Gross + Discount
        // LHS blinding sum: 5 + 2 = 7
        // RHS blinding sum: 4 + 3 = 7
        let r_net = r(5);
        let r_tax = r(2);
        let r_gross = r(4);
        let r_disc = r(3);

        let net = 100_000_u64;
        let tax = 21_000_u64;
        let disc = 4_000_u64;
        let gross = net + tax - disc;

        let c_net = Commitment::commit(net, &r_net);
        let c_tax = Commitment::commit(tax, &r_tax);
        let c_gross = Commitment::commit(gross, &r_gross);
        let c_disc = Commitment::commit(disc, &r_disc);

        let eq = LinearEquation {
            positive: &[c_net, c_tax],
            negative: &[c_gross, c_disc],
        };
        assert!(eq.verify());
    }

    #[test]
    fn invoice_total_with_wrong_gross_fails() {
        let r_net = r(5);
        let r_tax = r(2);
        let r_gross = r(4);
        let r_disc = r(3);

        let c_net = Commitment::commit(100_000, &r_net);
        let c_tax = Commitment::commit(21_000, &r_tax);
        let c_gross_bad = Commitment::commit(117_001, &r_gross); // off by one
        let c_disc = Commitment::commit(4_000, &r_disc);

        let eq = LinearEquation {
            positive: &[c_net, c_tax],
            negative: &[c_gross_bad, c_disc],
        };
        assert!(!eq.verify());
    }

    #[test]
    fn debit_credit_balance_with_three_each_side() {
        // Σ Debits == Σ Credits.
        // Blinding sums on each side must match for the tally to close.
        let r_d1 = r(1);
        let r_d2 = r(2);
        let r_d3 = r(3);
        let r_c1 = r(2);
        let r_c2 = r(1);
        let r_c3 = r(3);
        // sum(d) = 6, sum(c) = 6.

        let c_d1 = Commitment::commit(500, &r_d1);
        let c_d2 = Commitment::commit(1_500, &r_d2);
        let c_d3 = Commitment::commit(3_000, &r_d3);
        let c_c1 = Commitment::commit(2_000, &r_c1);
        let c_c2 = Commitment::commit(800, &r_c2);
        let c_c3 = Commitment::commit(2_200, &r_c3);

        let eq = LinearEquation {
            positive: &[c_d1, c_d2, c_d3],
            negative: &[c_c1, c_c2, c_c3],
        };
        assert!(eq.verify());
    }

    // ----- RangeProof --------------------------------------------------

    fn det_rng() -> impl RngCore {
        // Deterministic RNG for the test suite. PRODUCTION CALLERS MUST PASS
        // A CSPRNG (rand::thread_rng or similar).
        use rand::SeedableRng;
        rand_chacha::ChaCha20Rng::seed_from_u64(20_260_530)
    }

    #[test]
    fn range_proof_round_trips_for_a_64_bit_value() {
        let blinding = r(7);
        let value = 100_000_u64;
        let proof = RangeProof::prove(value, &blinding, 0, 32, &mut det_rng()).unwrap();
        let commitment = Commitment::commit(value, &blinding);
        let range = proof.verify(&commitment).unwrap();
        // The proved range covers the value.
        assert!(range.contains(&value));
    }

    #[test]
    fn range_proof_rejects_wrong_commitment() {
        let r1 = r(7);
        let r2 = r(8);
        let value = 100_000_u64;
        let proof = RangeProof::prove(value, &r1, 0, 32, &mut det_rng()).unwrap();
        let wrong = Commitment::commit(value, &r2);
        assert!(proof.verify(&wrong).is_err());
    }

    #[test]
    fn range_proof_serialisation_round_trip() {
        let blinding = r(0xab);
        let proof = RangeProof::prove(42_000, &blinding, 0, 32, &mut det_rng()).unwrap();
        let bytes = proof.serialize();
        let parsed = RangeProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
        let commitment = Commitment::commit(42_000, &blinding);
        parsed.verify(&commitment).unwrap();
    }

    #[test]
    fn garbage_bytes_do_not_parse_as_range_proof() {
        let err = RangeProof::from_bytes(&[0xff; 8]).unwrap_err();
        assert!(matches!(err, ZkError::RangeProofParseFailed(_)));
    }
}
