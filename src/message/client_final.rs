//! Parsing for client-final messages and their exact without-proof fragment.

use core::fmt;

use crate::{AttributeName, ProtocolError, ResourceLimits};

use super::{
    attribute::{AttributeScanner, expect, validate_nonce},
    base64::validate_base64,
    extensions::{ExtensionTracker, Extensions},
};

/// A validated client-final message retaining its authenticated fragments.
pub struct ClientFinal<'a> {
    raw: &'a [u8],
    without_proof: &'a [u8],
    channel_binding_base64: &'a [u8],
    nonce: &'a [u8],
    proof_base64: &'a [u8],
    extensions: Extensions<'a>,
}

impl<'a> ClientFinal<'a> {
    /// Parses one bounded client-final message without allocating.
    pub fn parse(input: &'a [u8], limits: &ResourceLimits) -> Result<Self, ProtocolError> {
        let mut scanner = AttributeScanner::new(input, limits)?;
        let binding = expect(&mut scanner, AttributeName::ChannelBinding)?;
        validate_base64(binding.value)?;
        let nonce = expect(&mut scanner, AttributeName::Nonce)?;
        validate_nonce(nonce.value, limits.max_nonce_bytes())?;
        let mut tracker = ExtensionTracker::new();
        loop {
            let Some(attribute) = scanner.next()? else {
                return Err(ProtocolError::MissingAttribute(AttributeName::Proof));
            };
            if attribute.name == b'p' {
                validate_base64(attribute.value)?;
                if scanner.next()?.is_some() {
                    return Err(ProtocolError::InvalidAttributeOrder);
                }
                let Some(without_proof_end) = attribute.start.checked_sub(1) else {
                    return Err(ProtocolError::MalformedMessage);
                };
                return Ok(Self {
                    raw: input,
                    without_proof: &input[..without_proof_end],
                    channel_binding_base64: binding.value,
                    nonce: nonce.value,
                    proof_base64: attribute.value,
                    extensions: tracker.finish(input),
                });
            }
            tracker.push(&attribute, limits)?;
        }
    }

    /// Returns the complete client-final message exactly as received.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the authenticated fragment before the `,p=` attribute.
    pub const fn without_proof(&self) -> &'a [u8] {
        self.without_proof
    }

    /// Returns the canonical Base64 GS2 header plus binding data.
    pub const fn channel_binding_base64(&self) -> &'a [u8] {
        self.channel_binding_base64
    }

    /// Returns the combined nonce.
    pub const fn nonce(&self) -> &'a [u8] {
        self.nonce
    }

    /// Returns the canonical Base64 proof without decoding it.
    pub const fn proof_base64(&self) -> &'a [u8] {
        self.proof_base64
    }

    /// Returns preserved unknown optional extensions.
    pub const fn extensions(&self) -> Extensions<'a> {
        self.extensions
    }
}

impl fmt::Debug for ClientFinal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientFinal")
            .field("length", &self.raw.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
