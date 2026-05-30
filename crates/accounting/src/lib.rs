// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Accounting equation library.
//!
//! Each accounting record is mapped to a data item anchored on BSV via the
//! Merkle Proof Entity (Layer A). Selective disclosure (Layer B) returns the
//! disclosed records for a query without revealing any other record. The
//! verifier then **recomputes** the accounting equation directly over those
//! disclosed `u64` records and rejects any equation that does not hold.
//!
//! The library carries the five accounting equations:
//!
//! 1. [`InvoiceTotal`]   — `Gross = Net + Tax − Discount`
//! 2. [`ArRollForward`]  — `AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs`
//! 3. [`DebitsCredits`]  — `Σ Debits = Σ Credits`
//! 4. [`BankReconciliation`] — `BookCash + ReconcilingItems = BankBalance`
//! 5. [`VatPayable`]     — `VAT_payable = OutputVAT − InputVAT`
//!
//! Boundary: the library checks the equation; it does not certify accounting
//! judgement (recognition under any accounting standard, classification,
//! related-party status, etc.). It also cannot detect a record entered
//! falsely at origin where the population is internally consistent — that is
//! the documented system boundary; see `docs/SECURITY.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// Errors returned by the accounting layer.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AccountingError {
    /// The equation did not hold under the disclosed records.
    #[error("accounting equation did not hold under the disclosed records")]
    EquationDoesNotHold,
    /// An arithmetic operation under-/over-flowed `u64` while recomputing.
    #[error("accounting equation overflowed u64 during recomputation")]
    Overflow,
}

// ---------------------------------------------------------------------------
// 1. Invoice total: Gross = Net + Tax − Discount  (minor units, u64)
// ---------------------------------------------------------------------------

/// `Gross = Net + Tax − Discount`. All values are minor units (`u64`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InvoiceTotal {
    /// Net amount (pre-tax, pre-discount).
    pub net: u64,
    /// Tax amount.
    pub tax: u64,
    /// Discount granted.
    pub discount: u64,
    /// Gross amount actually billed.
    pub gross: u64,
}

impl InvoiceTotal {
    /// Verify `Net + Tax == Gross + Discount` over the disclosed records.
    ///
    /// # Errors
    ///
    /// [`AccountingError::Overflow`] if either side overflows `u64`;
    /// [`AccountingError::EquationDoesNotHold`] if the sides differ.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let lhs = self
            .net
            .checked_add(self.tax)
            .ok_or(AccountingError::Overflow)?;
        let rhs = self
            .gross
            .checked_add(self.discount)
            .ok_or(AccountingError::Overflow)?;
        if lhs == rhs {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. AR roll-forward
// ---------------------------------------------------------------------------

/// Accounts-receivable roll-forward.
/// `AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs`.
/// Tally: `AR_open + Invoices == AR_close + Receipts + CreditNotes + WriteOffs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArRollForward {
    /// Opening accounts-receivable balance.
    pub ar_open: u64,
    /// Invoices issued in the period.
    pub invoices: u64,
    /// Closing accounts-receivable balance.
    pub ar_close: u64,
    /// Receipts in the period.
    pub receipts: u64,
    /// Credit notes issued in the period.
    pub credit_notes: u64,
    /// Receivables written off in the period.
    pub write_offs: u64,
}

impl ArRollForward {
    /// Verify the roll-forward identity over the disclosed records.
    ///
    /// # Errors
    ///
    /// [`AccountingError::Overflow`] on `u64` overflow;
    /// [`AccountingError::EquationDoesNotHold`] otherwise.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let lhs = self
            .ar_open
            .checked_add(self.invoices)
            .ok_or(AccountingError::Overflow)?;
        let rhs = self
            .ar_close
            .checked_add(self.receipts)
            .ok_or(AccountingError::Overflow)?
            .checked_add(self.credit_notes)
            .ok_or(AccountingError::Overflow)?
            .checked_add(self.write_offs)
            .ok_or(AccountingError::Overflow)?;
        if lhs == rhs {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Trial-balance: Σ Debits == Σ Credits
// ---------------------------------------------------------------------------

/// `Σ Debits == Σ Credits` over any number of debit/credit records.
#[derive(Clone, Copy, Debug)]
pub struct DebitsCredits<'a> {
    /// Slice of debit amounts (minor units).
    pub debits: &'a [u64],
    /// Slice of credit amounts (minor units).
    pub credits: &'a [u64],
}

impl DebitsCredits<'_> {
    /// Verify `Σ Debits == Σ Credits` over the disclosed records.
    ///
    /// # Errors
    ///
    /// [`AccountingError::Overflow`] on `u64` overflow during summation;
    /// [`AccountingError::EquationDoesNotHold`] if the sums differ.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let mut lhs: u64 = 0;
        for d in self.debits {
            lhs = lhs.checked_add(*d).ok_or(AccountingError::Overflow)?;
        }
        let mut rhs: u64 = 0;
        for c in self.credits {
            rhs = rhs.checked_add(*c).ok_or(AccountingError::Overflow)?;
        }
        if lhs == rhs {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Bank reconciliation
// ---------------------------------------------------------------------------

/// `BookCash + Σ ReconcilingItems == BankBalance`.
#[derive(Clone, Copy, Debug)]
pub struct BankReconciliation<'a> {
    /// Cash on the entity's books (minor units).
    pub book_cash: u64,
    /// Reconciling items (outstanding payments, deposits in transit, etc.).
    /// May be zero or many. Minor units.
    pub reconciling_items: &'a [u64],
    /// Bank balance per statement (minor units).
    pub bank_balance: u64,
}

impl BankReconciliation<'_> {
    /// Verify `BookCash + Σ ReconcilingItems == BankBalance`.
    ///
    /// # Errors
    ///
    /// [`AccountingError::Overflow`] on `u64` overflow;
    /// [`AccountingError::EquationDoesNotHold`] otherwise.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let mut lhs = self.book_cash;
        for v in self.reconciling_items {
            lhs = lhs.checked_add(*v).ok_or(AccountingError::Overflow)?;
        }
        if lhs == self.bank_balance {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

// ---------------------------------------------------------------------------
// 5. VAT payable
// ---------------------------------------------------------------------------

/// `VAT_payable = OutputVAT − InputVAT`. Tally: `OutputVAT == VAT_payable + InputVAT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VatPayable {
    /// Output VAT (charged on sales).
    pub output_vat: u64,
    /// Input VAT (recoverable on purchases).
    pub input_vat: u64,
    /// VAT payable to the tax authority.
    pub vat_payable: u64,
}

impl VatPayable {
    /// Verify `OutputVAT == VAT_payable + InputVAT` over the disclosed records.
    ///
    /// # Errors
    ///
    /// [`AccountingError::Overflow`] on `u64` overflow;
    /// [`AccountingError::EquationDoesNotHold`] otherwise.
    pub fn verify(&self) -> Result<(), AccountingError> {
        let rhs = self
            .vat_payable
            .checked_add(self.input_vat)
            .ok_or(AccountingError::Overflow)?;
        if self.output_vat == rhs {
            Ok(())
        } else {
            Err(AccountingError::EquationDoesNotHold)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoice_total_correct() {
        InvoiceTotal {
            net: 100_000,
            tax: 21_000,
            discount: 4_000,
            gross: 117_000,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn invoice_total_off_by_one_gross_is_rejected() {
        let err = InvoiceTotal {
            net: 100_000,
            tax: 21_000,
            discount: 4_000,
            gross: 117_001,
        }
        .verify()
        .unwrap_err();
        assert_eq!(err, AccountingError::EquationDoesNotHold);
    }

    #[test]
    fn invoice_total_overflow_detected() {
        let err = InvoiceTotal {
            net: u64::MAX,
            tax: 1,
            discount: 0,
            gross: 0,
        }
        .verify()
        .unwrap_err();
        assert_eq!(err, AccountingError::Overflow);
    }

    #[test]
    fn ar_roll_forward_correct() {
        ArRollForward {
            ar_open: 50_000,
            invoices: 60_000,
            ar_close: 40_000,
            receipts: 65_000,
            credit_notes: 3_000,
            write_offs: 2_000,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn ar_roll_forward_wrong_close_is_rejected() {
        let err = ArRollForward {
            ar_open: 50_000,
            invoices: 60_000,
            ar_close: 40_001,
            receipts: 65_000,
            credit_notes: 3_000,
            write_offs: 2_000,
        }
        .verify()
        .unwrap_err();
        assert_eq!(err, AccountingError::EquationDoesNotHold);
    }

    #[test]
    fn debits_credits_tally() {
        DebitsCredits {
            debits: &[500, 1_500, 3_000],
            credits: &[2_000, 800, 2_200],
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn debits_credits_unequal_rejected() {
        let err = DebitsCredits {
            debits: &[500, 1_500],
            credits: &[2_001],
        }
        .verify()
        .unwrap_err();
        assert_eq!(err, AccountingError::EquationDoesNotHold);
    }

    #[test]
    fn bank_reconciliation_with_items() {
        BankReconciliation {
            book_cash: 8_000,
            reconciling_items: &[2_000, 1_500],
            bank_balance: 11_500,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn bank_reconciliation_with_no_items() {
        BankReconciliation {
            book_cash: 10_000,
            reconciling_items: &[],
            bank_balance: 10_000,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn vat_payable_correct() {
        VatPayable {
            output_vat: 20_000,
            input_vat: 7_500,
            vat_payable: 12_500,
        }
        .verify()
        .unwrap();
    }

    #[test]
    fn vat_payable_off_by_one_rejected() {
        let err = VatPayable {
            output_vat: 20_000,
            input_vat: 7_500,
            vat_payable: 12_501,
        }
        .verify()
        .unwrap_err();
        assert_eq!(err, AccountingError::EquationDoesNotHold);
    }
}
