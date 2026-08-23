//! Deterministic nonce source for reproducible reference conversations.

use sasl_scram::{NonceError, NonceSource};

#[derive(Debug)]
pub(crate) struct FixedNonce([u8; 15]);

impl FixedNonce {
    pub(crate) const fn new(bytes: [u8; 15]) -> Self {
        Self(bytes)
    }
}

impl NonceSource for FixedNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        if output.len() != self.0.len() {
            return Err(NonceError::unavailable());
        }
        output.copy_from_slice(&self.0);
        Ok(())
    }
}
