use std::fmt;

/// An opaque envelope whose encoded length is fixed at compile time.
///
/// Encryption and protobuf integration deliberately live outside this type.
/// The future private transport must encrypt the entire array and must not
/// serialize its protected fields as variable-length outer protobuf fields.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct FixedEnvelope<const N: usize>([u8; N]);

impl<const N: usize> FixedEnvelope<N> {
    /// Builds an all-zero dummy envelope.
    pub(super) const fn zeroed() -> Self {
        Self([0; N])
    }

    /// Copies an exactly sized byte slice into a fixed envelope.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FixedEnvelopeError> {
        let actual = bytes.len();
        let data = bytes
            .try_into()
            .map_err(|_| FixedEnvelopeError::WrongLength {
                expected: N,
                actual,
            })?;
        Ok(Self(data))
    }

    /// Returns the fixed envelope bytes.
    pub(super) const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Consumes the envelope and returns its fixed byte array.
    fn into_bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> fmt::Debug for FixedEnvelope<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedEnvelope")
            .field("len", &N)
            .finish_non_exhaustive()
    }
}

/// A fixed envelope rejected an input with an observable outer length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedEnvelopeError {
    /// The byte slice did not match the envelope's compile-time size.
    WrongLength {
        /// Required byte length.
        expected: usize,
        /// Received byte length.
        actual: usize,
    },
}

impl fmt::Display for FixedEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "fixed envelope requires {expected} bytes; received {actual}"
                )
            }
        }
    }
}

impl std::error::Error for FixedEnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_preserves_exact_shape() -> Result<(), FixedEnvelopeError> {
        let bytes = [0x5a; 64];
        let envelope = FixedEnvelope::<64>::try_from_bytes(&bytes)?;
        assert_eq!(envelope.as_bytes(), &bytes);
        assert_eq!(envelope.into_bytes().len(), 64);
        Ok(())
    }

    #[test]
    fn envelope_rejects_every_non_exact_length() {
        assert_eq!(
            FixedEnvelope::<64>::try_from_bytes(&[0; 63]),
            Err(FixedEnvelopeError::WrongLength {
                expected: 64,
                actual: 63,
            })
        );
        assert_eq!(
            FixedEnvelope::<64>::try_from_bytes(&[0; 65]),
            Err(FixedEnvelopeError::WrongLength {
                expected: 64,
                actual: 65,
            })
        );
    }

    #[test]
    fn debug_output_does_not_expose_envelope_bytes() {
        let envelope = FixedEnvelope::<4>::try_from_bytes(&[1, 2, 3, 4])
            .expect("test fixture has the declared fixed length");
        let debug = format!("{envelope:?}");
        assert_eq!(debug, "FixedEnvelope { len: 4, .. }");
        assert!(!debug.contains("1, 2, 3, 4"));
    }
}
