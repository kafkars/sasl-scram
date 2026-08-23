//! Parsing for mutually exclusive server-final verifier and error outcomes.

use core::fmt;

use crate::{PeerError, ProtocolError, ResourceLimits};

use super::{
    attribute::{AttributeScanner, validate_value},
    base64::validate_base64,
    extensions::{ExtensionTracker, Extensions},
};

/// A borrowed canonical Base64 server verifier with explicit byte exposure.
#[derive(Clone, Copy)]
pub struct ServerVerifier<'a> {
    base64: &'a [u8],
}

impl<'a> ServerVerifier<'a> {
    /// Explicitly exposes the canonical Base64 bytes for protocol tooling.
    ///
    /// Authentication callers should use the consuming client state, which
    /// decodes and verifies this value in constant time.
    pub const fn expose_base64(self) -> &'a [u8] {
        self.base64
    }
}

impl fmt::Debug for ServerVerifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerVerifier")
            .field("length", &self.base64.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// A bounded server-final outcome that never retains unknown peer text.
///
/// Verifier bytes deliberately have no ordinary equality surface:
///
/// ```compile_fail
/// fn compare(outcome: sasl_scram::message::ServerFinalOutcome<'_>) {
///     let _same = outcome == outcome;
/// }
/// ```
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum ServerFinalOutcome<'a> {
    /// The server supplied a canonical Base64 verifier.
    Verified(ServerVerifier<'a>),
    /// The server supplied a mapped error classification.
    Rejected(PeerError),
}

impl fmt::Debug for ServerFinalOutcome<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(verifier) => formatter
                .debug_struct("Verified")
                .field("length", &verifier.base64.len())
                .field("contents", &"[REDACTED]")
                .finish(),
            Self::Rejected(error) => formatter.debug_tuple("Rejected").field(error).finish(),
        }
    }
}

/// A validated server-final message retaining its exact input.
pub struct ServerFinal<'a> {
    raw: &'a [u8],
    outcome: ServerFinalOutcome<'a>,
    extensions: Extensions<'a>,
}

impl<'a> ServerFinal<'a> {
    /// Parses one bounded server-final message without allocating.
    pub fn parse(input: &'a [u8], limits: &ResourceLimits) -> Result<Self, ProtocolError> {
        let mut scanner = AttributeScanner::new(input, limits)?;
        let Some(first) = scanner.next()? else {
            return Err(ProtocolError::MalformedMessage);
        };
        let outcome = match first.name {
            b'v' => {
                validate_base64(first.value)?;
                ServerFinalOutcome::Verified(ServerVerifier {
                    base64: first.value,
                })
            }
            b'e' if validate_value(first.value).is_ok() => {
                ServerFinalOutcome::Rejected(map_peer_error(first.value))
            }
            b'e' => return Err(ProtocolError::MalformedMessage),
            b'm' => return Err(ProtocolError::UnsupportedMandatoryExtension),
            _ => return Err(ProtocolError::InvalidAttributeOrder),
        };
        let mut tracker = ExtensionTracker::new();
        while let Some(attribute) = scanner.next()? {
            tracker.push(&attribute, limits)?;
        }
        Ok(Self {
            raw: input,
            outcome,
            extensions: tracker.finish(input),
        })
    }

    /// Returns the complete server-final message exactly as received.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the verifier or bounded peer-error outcome.
    pub const fn outcome(&self) -> ServerFinalOutcome<'a> {
        self.outcome
    }

    /// Returns preserved unknown optional extensions.
    pub const fn extensions(&self) -> Extensions<'a> {
        self.extensions
    }
}

impl fmt::Debug for ServerFinal<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerFinal")
            .field("length", &self.raw.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn map_peer_error(value: &[u8]) -> PeerError {
    match value {
        b"invalid-encoding" => PeerError::InvalidEncoding,
        b"extensions-not-supported" => PeerError::ExtensionsNotSupported,
        b"invalid-proof" => PeerError::InvalidProof,
        b"channel-bindings-dont-match" => PeerError::ChannelBindingsDoNotMatch,
        b"server-does-support-channel-binding" => PeerError::ServerSupportsChannelBinding,
        b"channel-binding-not-supported" => PeerError::ChannelBindingNotSupported,
        b"unsupported-channel-binding-type" => PeerError::UnsupportedChannelBindingType,
        b"unknown-user" => PeerError::UnknownUser,
        b"invalid-username-encoding" => PeerError::InvalidUsernameEncoding,
        b"no-resources" => PeerError::NoResources,
        b"other-error" => PeerError::OtherError,
        _ => PeerError::Other,
    }
}
