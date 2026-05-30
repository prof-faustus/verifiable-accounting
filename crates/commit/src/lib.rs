// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Pedersen commitments on secp256k1.
//!
//! `C(v, r) = v·G + r·H`, computed via Blockstream's `libsecp256k1-zkp`
//! (Rust binding crate `secp256k1-zkp`). The second generator `H` is a NUMS
//! point derived from a fixed domain-separation tag (see `docs/DECISIONS.md`
//! D-004); the derivation is reproducible from this source alone. No curve
//! arithmetic is implemented in this crate — all primitives come from
//! audited libraries (see `SECURITY.md`).
//!
//! ## Surface
//!
//! - [`Blinding`] — 32-byte scalar in the secp256k1 scalar field, wrapping
//!   `secp256k1_zkp::Tweak`.
//! - [`Commitment`] — opaque wrapper around `secp256k1_zkp::PedersenCommitment`,
//!   with a 33-byte stable serialisation for storage.
//! - [`Commitment::commit`] — produce `C(v, r)`.
//! - [`Commitment::verify_open`] — verify that a commitment opens to a given
//!   `(value, blinding)` pair.
//! - [`verify_sum_equal`] — verify that two slices of commitments tally to the
//!   same value (the homomorphic identity used by the linear-equation Σ-protocols
//!   in the `zk` crate).
//!
//! ## Boundary
//!
//! - `value: u64`. Range and validity proofs (non-negativity, currency bounds,
//!   no overflow, set membership for tax-rate / period) live in the `zk` crate
//!   (step 5).
//! - The crate caches a single `Secp256k1<All>` context and a single H generator
//!   via `OnceLock`. Both are immutable and shared across the process.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use std::sync::OnceLock;

use secp256k1_zkp::{All, Generator, PedersenCommitment, Secp256k1, Tag, Tweak};
use sha2::{Digest, Sha256};

/// Errors returned by the commit layer.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// The supplied blinding scalar was zero. Forbidden because it collapses
    /// `C(v, r) = v·G + r·H` to `C = v·G`, a deterministic function of the
    /// value alone — destroying the hiding property.
    #[error("blinding factor must be non-zero")]
    ZeroBlinding,
    /// The supplied 32-byte blinding was non-zero but outside the secp256k1
    /// group order `n`.
    #[error("invalid blinding factor: {0}")]
    InvalidBlinding(secp256k1_zkp::Error),
    /// The supplied bytes did not parse as a Pedersen commitment.
    #[error("invalid commitment encoding: {0}")]
    InvalidCommitment(secp256k1_zkp::Error),
}

/// Cached `Secp256k1<All>` context — single instance for the whole process.
fn secp() -> &'static Secp256k1<All> {
    static CTX: OnceLock<Secp256k1<All>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::new)
}

/// Cached Pedersen value-blinding generator H.
///
/// `H = Generator::new_unblinded(secp, Tag(SHA-256("VAA-Pedersen-H-v1")))`.
/// Anyone can verify the derivation by running
/// `sha2::Sha256::digest(b"VAA-Pedersen-H-v1")` to obtain the 32-byte tag.
fn h_generator() -> &'static Generator {
    static H: OnceLock<Generator> = OnceLock::new();
    H.get_or_init(|| {
        let tag_bytes: [u8; 32] = Sha256::digest(H_DOMAIN).into();
        let tag = Tag::from(tag_bytes);
        Generator::new_unblinded(secp(), tag)
    })
}

/// Domain-separation string for the Pedersen value-blinding generator H.
///
/// Recorded in `docs/DECISIONS.md` D-004. Changing this string changes H and
/// invalidates every previously-published commitment; the version suffix
/// (`-v1`) is the upgrade path.
pub const H_DOMAIN: &[u8] = b"VAA-Pedersen-H-v1";

/// Return the 32-byte SHA-256 tag used to derive H.
///
/// This is provided so external code (and the reproduce harness) can audit the
/// H derivation without depending on `sha2` directly.
#[must_use]
pub fn h_tag() -> [u8; 32] {
    Sha256::digest(H_DOMAIN).into()
}

/// Return the cached Pedersen value-blinding generator H.
///
/// Exposed so the `vaa-zk` crate (range proofs, Σ-protocol composition) can
/// pass the same H to `libsecp256k1-zkp` APIs that take a `Generator`
/// explicitly. There is exactly one H per process, derived from
/// [`H_DOMAIN`] via [`h_tag`].
#[must_use]
pub fn h_generator_point() -> Generator {
    *h_generator()
}

/// Return the cached process-wide `Secp256k1<All>` context.
///
/// Exposed for the same reason as [`h_generator_point`]: `libsecp256k1-zkp`
/// APIs (range proofs, sum-tally) take a context argument explicitly.
#[must_use]
pub fn secp_context() -> &'static Secp256k1<All> {
    secp()
}

/// A 32-byte blinding scalar for a Pedersen commitment.
///
/// Wraps `secp256k1_zkp::Tweak`. The scalar must be non-zero and below the
/// secp256k1 group order `n`; every constructor rejects invalid inputs, and
/// the `serde` deserialiser routes through [`Blinding::from_bytes`] so a
/// hand-crafted serialised zero is rejected on load (`CommitError::ZeroBlinding`)
/// instead of silently producing an insecure value.
///
/// The `Debug` impl is redacted (32 censored bytes) so blinding factors do
/// not appear in logs or panic messages.
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "[u8; 32]", into = "[u8; 32]")
)]
pub struct Blinding(Tweak);

impl Blinding {
    /// Construct from a 32-byte scalar.
    ///
    /// # Errors
    ///
    /// - [`CommitError::ZeroBlinding`] if `bytes` is the all-zero scalar.
    /// - [`CommitError::InvalidBlinding`] if `bytes` is non-zero but at or
    ///   above the secp256k1 group order `n`.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CommitError> {
        if bytes == [0u8; 32] {
            return Err(CommitError::ZeroBlinding);
        }
        Tweak::from_inner(bytes)
            .map(Self)
            .map_err(CommitError::InvalidBlinding)
    }

    /// Return the underlying 32-byte scalar.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_ref()
    }

    /// Expose the wrapped `Tweak` for use with `secp256k1-zkp` APIs that this
    /// crate does not re-export (e.g. range-proof construction in `vaa-zk`).
    #[must_use]
    pub fn as_tweak(&self) -> &Tweak {
        &self.0
    }
}

impl TryFrom<[u8; 32]> for Blinding {
    type Error = CommitError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl From<Blinding> for [u8; 32] {
    fn from(b: Blinding) -> Self {
        b.to_bytes()
    }
}

/// Custom `Debug` that does not print the inner scalar.
///
/// A blinding factor's secrecy underpins the hiding property of every
/// commitment that uses it; leaking it via logs or panic messages would
/// undo that. The redaction here is structural — the inner `Tweak`'s own
/// `Debug` prints raw bytes, so we override before it is reachable.
impl std::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blinding(<redacted 32 bytes>)")
    }
}

/// A Pedersen commitment `C(v, r) = v·G + r·H` over secp256k1.
///
/// The serialised form is 33 bytes (`serialize` / `from_bytes`) and is stable
/// across versions of `secp256k1-zkp` per the underlying library's contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commitment(PedersenCommitment);

impl Commitment {
    /// Commit to `value` under `blinding`.
    #[must_use]
    pub fn commit(value: u64, blinding: &Blinding) -> Self {
        Self(PedersenCommitment::new(
            secp(),
            value,
            blinding.0,
            *h_generator(),
        ))
    }

    /// Verify that this commitment opens to `(value, blinding)`.
    ///
    /// Equivalent to recomputing `C(value, blinding)` and comparing to `self`.
    /// Returns `true` only on bit-exact equality.
    #[must_use]
    pub fn verify_open(&self, value: u64, blinding: &Blinding) -> bool {
        Self::commit(value, blinding) == *self
    }

    /// 33-byte stable serialisation suitable for storage and on-chain
    /// anchoring.
    #[must_use]
    pub fn serialize(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Parse from the 33-byte serialisation produced by [`Commitment::serialize`].
    ///
    /// # Errors
    ///
    /// Returns [`CommitError::InvalidCommitment`] if `bytes` is not a valid
    /// 33-byte serialised Pedersen commitment (wrong length, or correct length
    /// but does not decode to a point on secp256k1).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CommitError> {
        PedersenCommitment::from_slice(bytes)
            .map(Self)
            .map_err(CommitError::InvalidCommitment)
    }

    /// Expose the wrapped `PedersenCommitment` for use with `secp256k1-zkp`
    /// APIs not re-exported here (e.g. range-proof verification).
    #[must_use]
    pub fn as_inner(&self) -> &PedersenCommitment {
        &self.0
    }
}

/// Verify that two sets of commitments tally to the same total committed value.
///
/// Returns `true` iff `Σ lhs.values == Σ rhs.values` **and** the blinding
/// factors tally so the point arithmetic closes. This is the primitive the
/// linear-equation Σ-protocols in `vaa-zk` build on: rearranging an equation
/// like `Gross = Net + Tax − Discount` into `Gross − Net − Tax + Discount = 0`
/// is exactly the case where both sides are equal under tally.
///
/// Both `lhs` and `rhs` may be empty; an empty-vs-empty check returns `true`.
#[must_use]
pub fn verify_sum_equal(lhs: &[Commitment], rhs: &[Commitment]) -> bool {
    let lhs_inner: Vec<PedersenCommitment> = lhs.iter().map(|c| c.0).collect();
    let rhs_inner: Vec<PedersenCommitment> = rhs.iter().map(|c| c.0).collect();
    secp256k1_zkp::verify_commitments_sum_to_equal(secp(), &lhs_inner, &rhs_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blinding that's just a repeating byte pattern. Useful for constructing
    /// `r1 + r2 = r3` test cases without modular-arithmetic helpers: as long
    /// as the per-byte sums don't overflow 0xff and the scalar stays below
    /// the curve order, addition in 256-bit big-endian integers equals
    /// per-byte addition.
    fn repeating(byte: u8) -> Blinding {
        Blinding::from_bytes([byte; 32]).expect("valid scalar")
    }

    // ------------------------------------------------------------------
    // Construction and opening
    // ------------------------------------------------------------------

    #[test]
    fn commit_then_verify_open_round_trips() {
        let r = repeating(7);
        let c = Commitment::commit(100_000, &r);
        assert!(c.verify_open(100_000, &r));
    }

    #[test]
    fn verify_open_rejects_wrong_value() {
        let r = repeating(7);
        let c = Commitment::commit(100_000, &r);
        assert!(!c.verify_open(99_999, &r));
        assert!(!c.verify_open(0, &r));
    }

    #[test]
    fn verify_open_rejects_wrong_blinding() {
        let r1 = repeating(7);
        let r2 = repeating(8);
        let c = Commitment::commit(100_000, &r1);
        assert!(!c.verify_open(100_000, &r2));
    }

    #[test]
    fn zero_blinding_rejected() {
        let err = Blinding::from_bytes([0u8; 32]).unwrap_err();
        assert!(matches!(err, CommitError::ZeroBlinding));
    }

    /// The secp256k1 group order `n`:
    /// `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
    fn n_bytes() -> [u8; 32] {
        let v = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    /// `n - 1`, the largest valid non-zero scalar in the secp256k1 scalar field.
    fn n_minus_one_bytes() -> [u8; 32] {
        let v = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn blinding_at_group_order_is_rejected() {
        let err = Blinding::from_bytes(n_bytes()).unwrap_err();
        assert!(matches!(err, CommitError::InvalidBlinding(_)));
    }

    #[test]
    fn blinding_at_group_order_minus_one_is_accepted() {
        let b = Blinding::from_bytes(n_minus_one_bytes()).unwrap();
        assert_eq!(b.to_bytes(), n_minus_one_bytes());
    }

    #[test]
    fn commitment_from_bytes_rejects_short_input() {
        let short = [0xc0u8; 32];
        assert!(matches!(
            Commitment::from_bytes(&short),
            Err(CommitError::InvalidCommitment(_))
        ));
    }

    #[test]
    fn commitment_from_bytes_rejects_long_input() {
        let long = [0xc0u8; 34];
        assert!(matches!(
            Commitment::from_bytes(&long),
            Err(CommitError::InvalidCommitment(_))
        ));
    }

    #[test]
    fn blinding_debug_is_redacted() {
        let r = Blinding::from_bytes([0x42u8; 32]).unwrap();
        let dbg = format!("{r:?}");
        assert!(
            dbg.contains("redacted"),
            "Debug must not leak blinding bytes; got: {dbg}"
        );
        // Negative: the raw scalar must not appear anywhere in the Debug output.
        assert!(!dbg.contains("4242"), "Debug leaked scalar bytes: {dbg}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_works_for_valid_blinding() {
        let r = Blinding::from_bytes([7u8; 32]).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let r2: Blinding = serde_json::from_str(&s).unwrap();
        assert_eq!(r.to_bytes(), r2.to_bytes());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_rejects_zero_blinding() {
        // Hand-craft the wire form a malicious peer would send.
        let zero_serialised = serde_json::to_string(&[0u8; 32]).unwrap();
        let err = serde_json::from_str::<Blinding>(&zero_serialised).expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("non-zero"),
            "expected zero-blinding rejection, got: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // Property tests
    // ------------------------------------------------------------------

    mod property {
        use super::*;
        use proptest::prelude::*;

        /// 32 random bytes, excluding the all-zero scalar.
        fn arb_nonzero_bytes() -> impl Strategy<Value = [u8; 32]> {
            prop::array::uniform32(any::<u8>()).prop_filter("non-zero", |b| *b != [0u8; 32])
        }

        /// A valid `Blinding` (non-zero, below the secp256k1 group order).
        fn arb_blinding() -> impl Strategy<Value = Blinding> {
            arb_nonzero_bytes().prop_filter_map("valid scalar (below curve order)", |b| {
                Blinding::from_bytes(b).ok()
            })
        }

        proptest! {
            #[test]
            fn open_round_trips(value: u64, r in arb_blinding()) {
                let c = Commitment::commit(value, &r);
                prop_assert!(c.verify_open(value, &r));
            }

            #[test]
            fn binding_sanity(
                value: u64,
                wrong: u64,
                r in arb_blinding(),
            ) {
                prop_assume!(value != wrong);
                let c = Commitment::commit(value, &r);
                prop_assert!(!c.verify_open(wrong, &r));
            }

            #[test]
            fn hiding_non_determinism(
                value: u64,
                r1 in arb_blinding(),
                r2 in arb_blinding(),
            ) {
                prop_assume!(r1.to_bytes() != r2.to_bytes());
                let c1 = Commitment::commit(value, &r1);
                let c2 = Commitment::commit(value, &r2);
                prop_assert_ne!(c1, c2);
                // Each still opens to its own (value, r) pair.
                prop_assert!(c1.verify_open(value, &r1));
                prop_assert!(c2.verify_open(value, &r2));
            }

            #[test]
            fn wrong_blinding_breaks_open(
                value: u64,
                r1 in arb_blinding(),
                r2 in arb_blinding(),
            ) {
                prop_assume!(r1.to_bytes() != r2.to_bytes());
                let c = Commitment::commit(value, &r1);
                prop_assert!(!c.verify_open(value, &r2));
            }

            #[test]
            fn equal_inputs_tally(value: u64, r in arb_blinding()) {
                // A single commitment trivially tallies against itself.
                let c = Commitment::commit(value, &r);
                prop_assert!(verify_sum_equal(&[c], &[c]));
            }

            #[test]
            fn distinct_value_totals_break_tally(
                a: u64,
                b: u64,
                r in arb_blinding(),
            ) {
                prop_assume!(a != b);
                let c_a = Commitment::commit(a, &r);
                let c_b = Commitment::commit(b, &r);
                prop_assert!(!verify_sum_equal(&[c_a], &[c_b]));
            }

            #[test]
            fn commitment_round_trips_through_bytes(
                value: u64,
                r in arb_blinding(),
            ) {
                let c = Commitment::commit(value, &r);
                let bytes = c.serialize();
                let parsed = Commitment::from_bytes(&bytes).unwrap();
                prop_assert_eq!(parsed, c);
            }
        }
    }

    // ------------------------------------------------------------------
    // Binding and hiding properties (sanity, not full proofs)
    // ------------------------------------------------------------------

    #[test]
    fn different_values_yield_different_commitments() {
        let r = repeating(7);
        let c1 = Commitment::commit(100_000, &r);
        let c2 = Commitment::commit(100_001, &r);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_blindings_yield_different_commitments_for_same_value() {
        let r1 = repeating(7);
        let r2 = repeating(8);
        let c1 = Commitment::commit(100_000, &r1);
        let c2 = Commitment::commit(100_000, &r2);
        assert_ne!(c1, c2);
        // Each still opens to its own (value, blinding) pair.
        assert!(c1.verify_open(100_000, &r1));
        assert!(c2.verify_open(100_000, &r2));
    }

    // ------------------------------------------------------------------
    // Homomorphic tally (the primitive the ZK layer builds on)
    // ------------------------------------------------------------------

    /// `C(a, r_a) + C(b, r_b) = C(a + b, r_a + r_b)` tallies to equal under
    /// `verify_sum_equal`. Constructed so byte-wise addition equals
    /// 256-bit-integer addition (no carries).
    #[test]
    fn sum_of_commitments_tallies_to_total() {
        let r_a = repeating(0x01);
        let r_b = repeating(0x02);
        let r_sum = repeating(0x03); // 0x01 + 0x02 per byte, no carry
        let c_a = Commitment::commit(100, &r_a);
        let c_b = Commitment::commit(200, &r_b);
        let c_total = Commitment::commit(300, &r_sum);
        assert!(verify_sum_equal(&[c_a, c_b], &[c_total]));
    }

    #[test]
    fn mismatched_value_total_fails_tally() {
        let r_a = repeating(0x01);
        let r_b = repeating(0x02);
        let r_sum = repeating(0x03);
        let c_a = Commitment::commit(100, &r_a);
        let c_b = Commitment::commit(200, &r_b);
        let c_total = Commitment::commit(301, &r_sum); // off by one
        assert!(!verify_sum_equal(&[c_a, c_b], &[c_total]));
    }

    #[test]
    fn mismatched_blinding_total_fails_tally() {
        let r_a = repeating(0x01);
        let r_b = repeating(0x02);
        let r_wrong = repeating(0x04); // not r_a + r_b
        let c_a = Commitment::commit(100, &r_a);
        let c_b = Commitment::commit(200, &r_b);
        let c_total = Commitment::commit(300, &r_wrong);
        assert!(!verify_sum_equal(&[c_a, c_b], &[c_total]));
    }

    #[test]
    fn empty_versus_empty_tallies() {
        assert!(verify_sum_equal(&[], &[]));
    }

    /// `Gross = Net + Tax − Discount` rearranged as
    /// `Net + Tax = Gross + Discount` is the tally form. Test the equality
    /// holds under matching blinding-factor sums.
    #[test]
    fn invoice_total_equation_tallies() {
        // Pick blindings whose per-byte sums match across the equation.
        // LHS sum = 0x05 + 0x02 = 0x07
        // RHS sum = 0x04 + 0x03 = 0x07
        let r_net = repeating(0x05);
        let r_tax = repeating(0x02);
        let r_gross = repeating(0x04);
        let r_discount = repeating(0x03);

        let net = 100_000;
        let tax = 21_000;
        let discount = 4_000;
        let gross = net + tax - discount; // 117_000

        let c_net = Commitment::commit(net, &r_net);
        let c_tax = Commitment::commit(tax, &r_tax);
        let c_gross = Commitment::commit(gross, &r_gross);
        let c_discount = Commitment::commit(discount, &r_discount);

        // Net + Tax  ==  Gross + Discount
        assert!(verify_sum_equal(&[c_net, c_tax], &[c_gross, c_discount],));

        // A wrong gross (off by one) should fail the tally.
        let c_gross_bad = Commitment::commit(gross + 1, &r_gross);
        assert!(!verify_sum_equal(
            &[c_net, c_tax],
            &[c_gross_bad, c_discount],
        ));
    }

    // ------------------------------------------------------------------
    // Serialisation
    // ------------------------------------------------------------------

    #[test]
    fn commitment_serialisation_round_trips() {
        let r = repeating(0x42);
        let c = Commitment::commit(123_456_789, &r);
        let bytes = c.serialize();
        assert_eq!(bytes.len(), 33);
        let parsed = Commitment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn commitment_from_bytes_rejects_garbage() {
        let garbage = [0xffu8; 33];
        let err = Commitment::from_bytes(&garbage).unwrap_err();
        assert!(matches!(err, CommitError::InvalidCommitment(_)));
    }

    #[test]
    fn blinding_round_trips_through_bytes() {
        let bytes = [0x12u8; 32];
        let b = Blinding::from_bytes(bytes).unwrap();
        assert_eq!(b.to_bytes(), bytes);
    }

    // ------------------------------------------------------------------
    // H derivation is reproducible
    // ------------------------------------------------------------------

    #[test]
    fn h_tag_is_sha256_of_domain_string() {
        let tag = h_tag();
        // Anyone can recompute this by running:
        //   echo -n "VAA-Pedersen-H-v1" | sha256sum
        // It should match what h_tag() returns. We assert the same
        // computation happens in code.
        let expected: [u8; 32] = Sha256::digest(b"VAA-Pedersen-H-v1").into();
        assert_eq!(tag, expected);
    }
}
