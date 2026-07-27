//! Pure transparent-chain event extraction for projection and corpus consumers.

use std::fmt;

use super::{AddrScript, CompactTxData, IndexedBlock, Outpoint, ScriptType, TxLocation};

/// One ordered transparent event extracted from an indexed block.
///
/// Standard P2PKH and P2SH outputs carry an exact [`AddrScript`]. The compact
/// block representation retains only a truncated payload for non-standard
/// scripts, so those outputs deliberately carry `address: None` rather than a
/// false address identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransparentBlockEvent {
    /// A transparent output created a new outpoint.
    Created {
        /// Transaction location of the creating transaction.
        location: TxLocation,
        /// Output position within the transaction.
        output_index: u16,
        /// Newly created outpoint.
        outpoint: Outpoint,
        /// Exact standard address identity, or `None` for a non-standard script.
        address: Option<AddrScript>,
        /// Output value in zatoshis.
        value_zat: u64,
        /// Compact script classification.
        script_class: ScriptType,
    },
    /// A transparent input spent a previous outpoint.
    Spent {
        /// Transaction location of the spending transaction.
        location: TxLocation,
        /// Input position within the transaction.
        input_index: u16,
        /// Previous outpoint consumed by the input.
        previous: Outpoint,
    },
}

impl fmt::Debug for TransparentBlockEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransparentBlockEvent { ..REDACTED.. }")
    }
}

/// A compact block could not be represented by the fixed event domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentEventError {
    /// A transaction index exceeded the `u16` event-layout field.
    TransactionIndexOverflow {
        /// Public block height containing the invalid index.
        height: u32,
        /// Rejected transaction index.
        index: usize,
    },
    /// An input index exceeded the `u16` event-layout field.
    InputIndexOverflow {
        /// Public block height containing the invalid index.
        height: u32,
        /// Transaction index containing the input.
        transaction_index: u16,
        /// Rejected input index.
        index: usize,
    },
    /// An output index exceeded the `u16` event-layout field.
    OutputIndexOverflow {
        /// Public block height containing the invalid index.
        height: u32,
        /// Transaction index containing the output.
        transaction_index: u16,
        /// Rejected output index.
        index: usize,
    },
    /// An output carried a script classification outside the compact enum.
    InvalidScriptClass {
        /// Public block height containing the invalid classification.
        height: u32,
        /// Transaction index containing the output.
        transaction_index: u16,
        /// Output index containing the invalid classification.
        output_index: u16,
        /// Rejected public script-class byte.
        script_class: u8,
    },
}

impl fmt::Display for TransparentEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionIndexOverflow { height, index } => write!(
                f,
                "transaction index {index} at height {height} exceeds the fixed u16 event domain"
            ),
            Self::InputIndexOverflow {
                height,
                transaction_index,
                index,
            } => write!(
                f,
                "input index {index} in transaction {transaction_index} at height {height} exceeds the fixed u16 event domain"
            ),
            Self::OutputIndexOverflow {
                height,
                transaction_index,
                index,
            } => write!(
                f,
                "output index {index} in transaction {transaction_index} at height {height} exceeds the fixed u16 event domain"
            ),
            Self::InvalidScriptClass {
                height,
                transaction_index,
                output_index,
                script_class,
            } => write!(
                f,
                "output {output_index} in transaction {transaction_index} at height {height} has invalid script class {script_class}"
            ),
        }
    }
}

impl std::error::Error for TransparentEventError {}

/// Extracts ordered transparent events without database or validator access.
///
/// Events preserve block and transaction order. Within each transaction,
/// spends precede creations. Coinbase null prevouts do not emit spend events.
pub fn extract_transparent_events(
    block: &IndexedBlock,
) -> Result<Vec<TransparentBlockEvent>, TransparentEventError> {
    let height = block.height().0;
    let mut events = Vec::new();
    for (transaction_index, transaction) in block.transactions().iter().enumerate() {
        let transaction_index = checked_transaction_index(height, transaction_index)?;
        extract_transaction_events(height, transaction_index, transaction, &mut events)?;
    }
    Ok(events)
}

fn extract_transaction_events(
    height: u32,
    transaction_index: u16,
    transaction: &CompactTxData,
    events: &mut Vec<TransparentBlockEvent>,
) -> Result<(), TransparentEventError> {
    let location = TxLocation::new(height, transaction_index);

    for (input_index, input) in transaction.transparent().inputs().iter().enumerate() {
        if input.is_null_prevout() {
            continue;
        }
        let input_index = checked_input_index(height, transaction_index, input_index)?;
        events.push(TransparentBlockEvent::Spent {
            location,
            input_index,
            previous: Outpoint::new(*input.prevout_txid(), input.prevout_index()),
        });
    }

    for (output_index, output) in transaction.transparent().outputs().iter().enumerate() {
        let output_index = checked_output_index(height, transaction_index, output_index)?;
        let script_class =
            output
                .script_type_enum()
                .ok_or(TransparentEventError::InvalidScriptClass {
                    height,
                    transaction_index,
                    output_index,
                    script_class: output.script_type(),
                })?;
        let address = match script_class {
            ScriptType::P2PKH | ScriptType::P2SH => {
                Some(AddrScript::new(*output.script_hash(), output.script_type()))
            }
            ScriptType::NonStandard => None,
        };
        events.push(TransparentBlockEvent::Created {
            location,
            output_index,
            outpoint: Outpoint::new(transaction.txid().0, u32::from(output_index)),
            address,
            value_zat: output.value(),
            script_class,
        });
    }

    Ok(())
}

fn checked_transaction_index(height: u32, index: usize) -> Result<u16, TransparentEventError> {
    u16::try_from(index)
        .map_err(|_| TransparentEventError::TransactionIndexOverflow { height, index })
}

fn checked_input_index(
    height: u32,
    transaction_index: u16,
    index: usize,
) -> Result<u16, TransparentEventError> {
    u16::try_from(index).map_err(|_| TransparentEventError::InputIndexOverflow {
        height,
        transaction_index,
        index,
    })
}

fn checked_output_index(
    height: u32,
    transaction_index: u16,
    index: usize,
) -> Result<u16, TransparentEventError> {
    u16::try_from(index).map_err(|_| TransparentEventError::OutputIndexOverflow {
        height,
        transaction_index,
        index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompactTxData, OrchardCompactTx, SaplingCompactTx, TransactionHash, TransparentCompactTx,
        TxInCompact, TxOutCompact,
    };

    fn transaction(
        txid_byte: u8,
        inputs: Vec<TxInCompact>,
        outputs: Vec<TxOutCompact>,
    ) -> CompactTxData {
        CompactTxData::new(
            0,
            TransactionHash([txid_byte; 32]),
            TransparentCompactTx::new(inputs, outputs),
            SaplingCompactTx::new(None, Vec::new(), Vec::new()),
            OrchardCompactTx::empty(),
            OrchardCompactTx::empty(),
        )
    }

    fn output(byte: u8, script_class: ScriptType) -> TxOutCompact {
        TxOutCompact::new(50, [byte; 20], script_class as u8)
            .expect("known script class constructs a compact output")
    }

    #[test]
    fn extracts_standard_and_nonstandard_outputs_without_false_identity(
    ) -> Result<(), TransparentEventError> {
        let tx = transaction(
            7,
            Vec::new(),
            vec![
                output(1, ScriptType::P2PKH),
                output(2, ScriptType::P2SH),
                output(3, ScriptType::NonStandard),
            ],
        );
        let mut events = Vec::new();
        extract_transaction_events(10, 2, &tx, &mut events)?;

        assert_eq!(events.len(), 3);
        assert!(matches!(
            events[0],
            TransparentBlockEvent::Created {
                location,
                output_index: 0,
                address: Some(address),
                script_class: ScriptType::P2PKH,
                ..
            } if location == TxLocation::new(10, 2)
                && address == AddrScript::new([1; 20], ScriptType::P2PKH as u8)
        ));
        assert!(matches!(
            events[1],
            TransparentBlockEvent::Created {
                output_index: 1,
                address: Some(address),
                script_class: ScriptType::P2SH,
                ..
            } if address == AddrScript::new([2; 20], ScriptType::P2SH as u8)
        ));
        assert!(matches!(
            events[2],
            TransparentBlockEvent::Created {
                output_index: 2,
                address: None,
                script_class: ScriptType::NonStandard,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn skips_coinbase_and_orders_spends_before_creations() -> Result<(), TransparentEventError> {
        let previous = [9; 32];
        let tx = transaction(
            8,
            vec![TxInCompact::null_prevout(), TxInCompact::new(previous, 4)],
            vec![output(1, ScriptType::P2PKH)],
        );
        let mut events = Vec::new();
        extract_transaction_events(11, 3, &tx, &mut events)?;

        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            TransparentBlockEvent::Spent {
                input_index: 1,
                previous: outpoint,
                ..
            } if outpoint == Outpoint::new(previous, 4)
        ));
        assert!(matches!(events[1], TransparentBlockEvent::Created { .. }));
        Ok(())
    }

    #[test]
    fn index_overflow_errors_are_typed_and_identifier_free() {
        let overflow = usize::from(u16::MAX) + 1;
        assert_eq!(
            checked_transaction_index(12, overflow),
            Err(TransparentEventError::TransactionIndexOverflow {
                height: 12,
                index: overflow,
            })
        );
        assert_eq!(
            checked_input_index(12, 4, overflow),
            Err(TransparentEventError::InputIndexOverflow {
                height: 12,
                transaction_index: 4,
                index: overflow,
            })
        );
        assert_eq!(
            checked_output_index(12, 4, overflow),
            Err(TransparentEventError::OutputIndexOverflow {
                height: 12,
                transaction_index: 4,
                index: overflow,
            })
        );
    }

    #[test]
    fn event_debug_output_is_redacted() -> Result<(), TransparentEventError> {
        let tx = transaction(0x7a, Vec::new(), vec![output(0x6b, ScriptType::P2PKH)]);
        let mut events = Vec::new();
        extract_transaction_events(13, 0, &tx, &mut events)?;
        let debug = format!("{:?}", events[0]);
        assert_eq!(debug, "TransparentBlockEvent { ..REDACTED.. }");
        assert!(!debug.contains("7a"));
        assert!(!debug.contains("6b"));
        Ok(())
    }
}
