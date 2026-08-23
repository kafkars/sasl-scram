//! Injected nonce generation without ambient randomness.

/// An opaque nonce-source failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceError;

impl NonceError {
    /// Creates a failure without attaching source text.
    pub const fn unavailable() -> Self {
        Self
    }
}

/// A caller-owned source of unpredictable nonce bytes.
pub trait NonceSource {
    /// Fills the complete output buffer or returns an opaque failure.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError>;
}
