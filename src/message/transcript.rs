//! Exact authentication transcript assembly from validated message views.

use core::fmt;

use crate::{OutboundMessage, ProtocolError, ResourceLimits};

use super::{ClientFinal, ClientFirst, ServerFirst};

/// Borrowed exact fragments of the SCRAM `AuthMessage`.
pub struct AuthenticationTranscript<'a> {
    client_first_bare: &'a [u8],
    server_first: &'a [u8],
    client_final_without_proof: &'a [u8],
}

impl<'a> AuthenticationTranscript<'a> {
    pub(crate) const fn from_fragments(
        client_first_bare: &'a [u8],
        server_first: &'a [u8],
        client_final_without_proof: &'a [u8],
    ) -> Self {
        Self {
            client_first_bare,
            server_first,
            client_final_without_proof,
        }
    }

    /// Selects exact fragments from three already validated message views.
    pub const fn from_messages(
        client_first: &ClientFirst<'a>,
        server_first: &ServerFirst<'a>,
        client_final: &ClientFinal<'a>,
    ) -> Self {
        Self::from_fragments(
            client_first.bare(),
            server_first.raw(),
            client_final.without_proof(),
        )
    }

    /// Returns the five fragments in authentication order, including separators.
    pub const fn fragments(&self) -> [&'a [u8]; 5] {
        [
            self.client_first_bare,
            b",",
            self.server_first,
            b",",
            self.client_final_without_proof,
        ]
    }

    /// Explicitly copies the complete transcript into redacted, zeroizing ownership.
    pub fn to_owned_message(
        &self,
        limits: &ResourceLimits,
    ) -> Result<OutboundMessage, ProtocolError> {
        let length = self
            .fragments()
            .iter()
            .try_fold(0_usize, |total, fragment| total.checked_add(fragment.len()))
            .unwrap_or(usize::MAX);
        let maximum = limits
            .max_message_bytes()
            .saturating_mul(3)
            .saturating_add(2);
        if length == usize::MAX || length > maximum {
            return Err(ProtocolError::MessageTooLarge { length, maximum });
        }
        let mut output = alloc::vec::Vec::with_capacity(length);
        for fragment in self.fragments() {
            output.extend_from_slice(fragment);
        }
        Ok(OutboundMessage::new(output))
    }
}

impl fmt::Debug for AuthenticationTranscript<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let length = self.fragments().iter().fold(0_usize, |total, fragment| {
            total.saturating_add(fragment.len())
        });
        formatter
            .debug_struct("AuthenticationTranscript")
            .field("length", &length)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
