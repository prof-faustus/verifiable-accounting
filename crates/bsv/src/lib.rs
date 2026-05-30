// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! BSV (Bitcoin SV) primitive types for the Verifiable Accounting Arithmetic
//! reference implementation.
//!
//! This crate is the BSV boundary of the workspace. Other crates (`merkle`,
//! `proofstore`) depend on it for the BSV double-SHA256 hash, txid/header
//! types, transaction/script model, and the SPV header-chain glue. No other
//! crate computes a BSV hash or parses a BSV transaction directly.
//!
//! BSV is fixed as the target platform; see `docs/DECISIONS.md` D-002.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Hashing primitives.
///
/// The single supported hash is BSV double-SHA256: `H(x) = SHA256(SHA256(x))`.
/// There is no single-SHA256 mode by design.
pub mod hash {
    use sha2::{Digest, Sha256};

    /// Compute the BSV double-SHA256 of `input`.
    ///
    /// Returns the 32-byte digest in the standard byte order used by Bitcoin
    /// when computing hashes (internal little-endian for txids; the caller is
    /// responsible for any display-time big-endian reversal).
    #[must_use]
    pub fn double_sha256(input: &[u8]) -> [u8; 32] {
        let first = Sha256::digest(input);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bitcoin double-SHA256 of the empty string. Known constant.
    #[test]
    fn double_sha256_empty_matches_known_vector() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let h = hash::double_sha256(b"");
        let expected =
            hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
                .unwrap();
        assert_eq!(&h[..], &expected[..]);
    }
}
