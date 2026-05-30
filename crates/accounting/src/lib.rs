// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Accounting equation library and validity rules.
//!
//! Defines the equations that the ZK layer proves over committed accounting
//! values. All five equations enumerated below are linear in the
//! committed values, which is the design constraint enabling Σ-protocol proofs
//! (see `docs/DECISIONS.md` D-003).
//!
//! The equations are:
//!
//! 1. [`InvoiceTotal`]   — `Gross = Net + Tax − Discount`
//! 2. [`ArRollForward`]  — `AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs`
//! 3. [`DebitsCredits`]  — `Σ Debits = Σ Credits`
//! 4. [`BankReconciliation`] — `BookCash + ReconcilingItems = BankBalance`
//! 5. [`VatPayable`]     — `VAT_payable = OutputVAT − InputVAT`
//!
//! Each struct accepts pre-committed Pedersen commitments and verifies the
//! equation via the underlying tally. The blinding factors used by the
//! prover MUST tally on the same partition as the values, or the proof will
//! be rejected even though the values are arithmetically correct — this is
//! intentional: it binds the prover to a consistent set of openings.
//!
//! ## Boundary
//!
//! The library encodes accounting equations as mathematical identities over
//! committed values. It does not certify accounting judgement: whether a
//! particular figure represents revenue under IFRS 15, or is correctly
//! classified between current and non-current, is outside the system. See
//! `docs/SECURITY.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

use vaa_commit::Commitment;
use vaa_zk::LinearEquation;

/// Errors returned by the accounting layer.
#[derive(Debug, thiserror::Error)]
pub enum AccountingError {
    /// The equation's tally over the committed values did not close.
    #[error("accounting equation did not hold under the committed openings")]
    EquationDoesNotHold,
}

// ---------------------------------------------------------------------------
// 1. Invoice total: Gross = Net + Tax − Discount
// ---------------------------------------------------------------------------

/// `Gross = Net + Tax − Discount`. Rearranged for tally:
/// `Net + Tax == Gross + Discount`.
#[derive(Clone, Copy, Debug)]
pub struct InvoiceTotal {
    /// Net amount (pre-tax, pre-discount).
    pub net: Commitment,
    /// Tax amount.
    pub tax: Commitment,
    /// Discount granted.
    pub discount: Commitment,
    /// Gross amount actually billed.
    pub gross: Commitment,
}

impl InvoiceTotal {
    /// Verify `Net + Tax == Gross + Discount`.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::EquationDoesNotHold`] if the tally fails.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let positive = [self.net, self.tax];
        let negative = [self.gross, self.discount];
        if (LinearEquation {
            positive: &positive,
            negative: &negative,
        })
        .verify()
        {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. AR roll-forward: AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs
// ---------------------------------------------------------------------------

/// Accounts-receivable roll-forward.
/// `AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs`.
/// Tally form: `AR_open + Invoices == AR_close + Receipts + CreditNotes + WriteOffs`.
#[derive(Clone, Copy, Debug)]
pub struct ArRollForward {
    /// Opening accounts-receivable balance.
    pub ar_open: Commitment,
    /// Invoices issued in the period.
    pub invoices: Commitment,
    /// Closing accounts-receivable balance.
    pub ar_close: Commitment,
    /// Cash receipts in the period.
    pub receipts: Commitment,
    /// Credit notes issued in the period.
    pub credit_notes: Commitment,
    /// Receivables written off in the period.
    pub write_offs: Commitment,
}

impl ArRollForward {
    /// Verify `AR_open + Invoices == AR_close + Receipts + CreditNotes + WriteOffs`.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::EquationDoesNotHold`] if the tally fails.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let positive = [self.ar_open, self.invoices];
        let negative = [
            self.ar_close,
            self.receipts,
            self.credit_notes,
            self.write_offs,
        ];
        if (LinearEquation {
            positive: &positive,
            negative: &negative,
        })
        .verify()
        {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Trial-balance: Σ Debits == Σ Credits
// ---------------------------------------------------------------------------

/// `Σ Debits == Σ Credits` over any number of debit / credit commitments.
#[derive(Clone, Debug)]
pub struct DebitsCredits<'a> {
    /// Slice of debit commitments.
    pub debits: &'a [Commitment],
    /// Slice of credit commitments.
    pub credits: &'a [Commitment],
}

impl DebitsCredits<'_> {
    /// Verify `Σ Debits == Σ Credits`.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::EquationDoesNotHold`] if the tally fails.
    pub fn verify(&self) -> Result<(), AccountingError> {
        if (LinearEquation {
            positive: self.debits,
            negative: self.credits,
        })
        .verify()
        {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Bank reconciliation: BookCash + ReconcilingItems = BankBalance
// ---------------------------------------------------------------------------

/// `BookCash + ReconcilingItems == BankBalance`.
#[derive(Clone, Debug)]
pub struct BankReconciliation<'a> {
    /// Cash on the entity's books.
    pub book_cash: Commitment,
    /// Reconciling items (outstanding cheques, deposits in transit, bank
    /// errors, etc.). May be zero or many.
    pub reconciling_items: &'a [Commitment],
    /// Bank balance per statement.
    pub bank_balance: Commitment,
}

impl BankReconciliation<'_> {
    /// Verify `BookCash + Σ ReconcilingItems == BankBalance`.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::EquationDoesNotHold`] if the tally fails.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let mut positive: Vec<Commitment> = Vec::with_capacity(1 + self.reconciling_items.len());
        positive.push(self.book_cash);
        positive.extend_from_slice(self.reconciling_items);
        let negative = [self.bank_balance];
        if (LinearEquation {
            positive: &positive,
            negative: &negative,
        })
        .verify()
        {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 5. VAT payable: VAT_payable = OutputVAT − InputVAT
// ---------------------------------------------------------------------------

/// `VAT_payable = OutputVAT − InputVAT`. Tally form:
/// `OutputVAT == VAT_payable + InputVAT`.
#[derive(Clone, Copy, Debug)]
pub struct VatPayable {
    /// Output VAT (VAT charged on sales).
    pub output_vat: Commitment,
    /// Input VAT (VAT recoverable on purchases).
    pub input_vat: Commitment,
    /// VAT payable to the tax authority.
    pub vat_payable: Commitment,
}

impl VatPayable {
    /// Verify `OutputVAT == VAT_payable + InputVAT`.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::EquationDoesNotHold`] if the tally fails.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let positive = [self.output_vat];
        let negative = [self.vat_payable, self.input_vat];
        if (LinearEquation {
            positive: &positive,
            negative: &negative,
        })
        .verify()
        {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaa_commit::Blinding;

    fn r(byte: u8) -> Blinding {
        Blinding::from_bytes([byte; 32]).expect("valid scalar")
    }

    // ------- Invoice total -------

    #[test]
    fn invoice_total_correct() {
        // LHS blindings (Net + Tax) sum: 5 + 2 = 7
        // RHS blindings (Gross + Discount) sum: 4 + 3 = 7
        let net = Commitment::commit(100_000, &r(5));
        let tax = Commitment::commit(21_000, &r(2));
        let discount = Commitment::commit(4_000, &r(3));
        let gross = Commitment::commit(117_000, &r(4));
        InvoiceTotal {
            net,
            tax,
            discount,
            gross,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn invoice_total_off_by_one_gross_is_rejected() {
        let net = Commitment::commit(100_000, &r(5));
        let tax = Commitment::commit(21_000, &r(2));
        let discount = Commitment::commit(4_000, &r(3));
        let gross = Commitment::commit(117_001, &r(4)); // wrong
        let err = InvoiceTotal {
            net,
            tax,
            discount,
            gross,
        }
        .verify()
        .unwrap_err();
        assert!(matches!(err, AccountingError::EquationDoesNotHold));
    }

    // ------- AR roll-forward -------

    #[test]
    fn ar_roll_forward_correct() {
        // LHS: ar_open (10) + invoices (1) = 11
        // RHS: ar_close (3) + receipts (4) + credit_notes (2) + write_offs (2) = 11
        let ar_open = Commitment::commit(50_000, &r(10));
        let invoices = Commitment::commit(60_000, &r(1));
        let ar_close = Commitment::commit(40_000, &r(3));
        let receipts = Commitment::commit(65_000, &r(4));
        let credit_notes = Commitment::commit(3_000, &r(2));
        let write_offs = Commitment::commit(2_000, &r(2));
        ArRollForward {
            ar_open,
            invoices,
            ar_close,
            receipts,
            credit_notes,
            write_offs,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn ar_roll_forward_wrong_close_is_rejected() {
        let ar_open = Commitment::commit(50_000, &r(10));
        let invoices = Commitment::commit(60_000, &r(1));
        let ar_close = Commitment::commit(40_001, &r(3)); // off by one
        let receipts = Commitment::commit(65_000, &r(4));
        let credit_notes = Commitment::commit(3_000, &r(2));
        let write_offs = Commitment::commit(2_000, &r(2));
        let err = ArRollForward {
            ar_open,
            invoices,
            ar_close,
            receipts,
            credit_notes,
            write_offs,
        }
        .verify()
        .unwrap_err();
        assert!(matches!(err, AccountingError::EquationDoesNotHold));
    }

    // ------- Debits == Credits -------

    #[test]
    fn debits_credits_tally() {
        let debits = [
            Commitment::commit(500, &r(1)),
            Commitment::commit(1_500, &r(2)),
            Commitment::commit(3_000, &r(3)),
        ];
        let credits = [
            Commitment::commit(2_000, &r(2)),
            Commitment::commit(800, &r(1)),
            Commitment::commit(2_200, &r(3)),
        ];
        DebitsCredits {
            debits: &debits,
            credits: &credits,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn debits_credits_unequal_sides_rejected() {
        let debits = [
            Commitment::commit(500, &r(1)),
            Commitment::commit(1_500, &r(2)),
        ];
        let credits = [Commitment::commit(2_001, &r(3))]; // off by one
        let err = DebitsCredits {
            debits: &debits,
            credits: &credits,
        }
        .verify()
        .unwrap_err();
        assert!(matches!(err, AccountingError::EquationDoesNotHold));
    }

    // ------- Bank reconciliation -------

    #[test]
    fn bank_reconciliation_with_two_items() {
        // book_cash (5) + items (2 + 3 = 5) = 10; bank_balance (10)
        let book_cash = Commitment::commit(8_000, &r(5));
        let items = [
            Commitment::commit(2_000, &r(2)),
            Commitment::commit(1_500, &r(3)),
        ];
        let bank_balance = Commitment::commit(11_500, &r(10));
        BankReconciliation {
            book_cash,
            reconciling_items: &items,
            bank_balance,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn bank_reconciliation_with_no_items() {
        let book_cash = Commitment::commit(10_000, &r(5));
        let bank_balance = Commitment::commit(10_000, &r(5));
        BankReconciliation {
            book_cash,
            reconciling_items: &[],
            bank_balance,
        }
        .verify()
        .unwrap();
    }

    // ------- VAT -------

    #[test]
    fn vat_payable_correct() {
        // output (10) == payable (7) + input (3)
        let output_vat = Commitment::commit(20_000, &r(10));
        let input_vat = Commitment::commit(7_500, &r(3));
        let vat_payable = Commitment::commit(12_500, &r(7));
        VatPayable {
            output_vat,
            input_vat,
            vat_payable,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn vat_payable_off_by_one_rejected() {
        let output_vat = Commitment::commit(20_000, &r(10));
        let input_vat = Commitment::commit(7_500, &r(3));
        let vat_payable = Commitment::commit(12_501, &r(7)); // off
        let err = VatPayable {
            output_vat,
            input_vat,
            vat_payable,
        }
        .verify()
        .unwrap_err();
        assert!(matches!(err, AccountingError::EquationDoesNotHold));
    }
}
