//! Parsing for the GS2 header and client-first-message-bare transcript.

use alloc::boxed::Box;
use core::fmt;

use crate::{ProtocolError, ResourceLimits, channel_binding::is_valid_channel_binding_name};

use super::attribute::{
    AttributeScanner, ensure_message_limit, expect, validate_identity, validate_nonce,
};
use super::extensions::{ExtensionTracker, Extensions};
use super::identity;
use crate::AttributeName;

/// A borrowed GS2 channel-binding flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Gs2Flag<'a> {
    /// Channel binding is unsupported (`n`).
    Unsupported,
    /// Channel binding is available locally but not negotiated (`y`).
    AvailableButNotNegotiated,
    /// Channel binding is required with the borrowed binding name (`p=`).
    Required(&'a [u8]),
}

/// A validated client-first message retaining its exact input and bare fragment.
pub struct ClientFirst<'a> {
    raw: &'a [u8],
    gs2_header: &'a [u8],
    bare: &'a [u8],
    flag: Gs2Flag<'a>,
    authorization_identity: Option<&'a [u8]>,
    authentication_identity: &'a [u8],
    nonce: &'a [u8],
    extensions: Extensions<'a>,
}

impl<'a> ClientFirst<'a> {
    /// Parses one bounded client-first message without allocating.
    pub fn parse(input: &'a [u8], limits: &ResourceLimits) -> Result<Self, ProtocolError> {
        ensure_message_limit(input, limits)?;
        let Some(first_comma) = input.iter().position(|byte| *byte == b',') else {
            return Err(ProtocolError::MalformedMessage);
        };
        let after_first = first_comma + 1;
        let Some(second_relative) = input[after_first..].iter().position(|byte| *byte == b',')
        else {
            return Err(ProtocolError::MalformedMessage);
        };
        let second_comma = after_first + second_relative;
        let bare_start = second_comma + 1;
        if bare_start == input.len() {
            return Err(ProtocolError::MalformedMessage);
        }
        let flag = parse_flag(&input[..first_comma])?;
        let authorization_identity = parse_authorization_identity(
            &input[after_first..second_comma],
            limits.max_authorization_identity_bytes(),
        )?;
        let bare = &input[bare_start..];
        let mut scanner = AttributeScanner::new(bare, limits)?;
        let identity = expect(&mut scanner, AttributeName::AuthenticationIdentity)?;
        validate_identity(identity.value, limits.max_identity_bytes())?;
        let nonce = expect(&mut scanner, AttributeName::Nonce)?;
        validate_nonce(nonce.value, limits.max_nonce_bytes())?;
        let mut tracker = ExtensionTracker::new();
        while let Some(attribute) = scanner.next()? {
            tracker.push(&attribute, limits)?;
        }
        Ok(Self {
            raw: input,
            gs2_header: &input[..bare_start],
            bare,
            flag,
            authorization_identity,
            authentication_identity: identity.value,
            nonce: nonce.value,
            extensions: tracker.finish(bare),
        })
    }

    /// Returns the complete input exactly as received.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the exact GS2 header including its trailing comma.
    pub const fn gs2_header(&self) -> &'a [u8] {
        self.gs2_header
    }

    /// Returns the exact client-first-message-bare transcript fragment.
    pub const fn bare(&self) -> &'a [u8] {
        self.bare
    }

    /// Returns the parsed GS2 channel-binding flag.
    pub const fn channel_binding_flag(&self) -> Gs2Flag<'a> {
        self.flag
    }

    /// Returns the optional escaped authorization identity.
    pub const fn authorization_identity(&self) -> Option<&'a [u8]> {
        self.authorization_identity
    }

    /// Returns the escaped authentication identity.
    pub const fn authentication_identity(&self) -> &'a [u8] {
        self.authentication_identity
    }

    /// Decodes and owns the authentication identity after validating SCRAM escapes.
    pub fn decode_authentication_identity(&self) -> Result<Box<str>, ProtocolError> {
        identity::decode(self.authentication_identity, usize::MAX)
    }

    /// Decodes and owns the optional authorization identity.
    pub fn decode_authorization_identity(&self) -> Result<Option<Box<str>>, ProtocolError> {
        self.authorization_identity
            .map(|value| identity::decode(value, usize::MAX))
            .transpose()
    }

    /// Returns the client nonce.
    pub const fn nonce(&self) -> &'a [u8] {
        self.nonce
    }

    /// Returns preserved unknown optional extensions.
    pub const fn extensions(&self) -> Extensions<'a> {
        self.extensions
    }
}

impl fmt::Debug for ClientFirst<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientFirst")
            .field("length", &self.raw.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn parse_flag(value: &[u8]) -> Result<Gs2Flag<'_>, ProtocolError> {
    match value {
        b"n" => Ok(Gs2Flag::Unsupported),
        b"y" => Ok(Gs2Flag::AvailableButNotNegotiated),
        binding if binding.starts_with(b"p=") && is_valid_channel_binding_name(&binding[2..]) => {
            Ok(Gs2Flag::Required(&binding[2..]))
        }
        binding if binding.starts_with(b"p=") => Err(ProtocolError::InvalidChannelBindingName),
        _ => Err(ProtocolError::MalformedMessage),
    }
}

fn parse_authorization_identity(
    value: &[u8],
    maximum: usize,
) -> Result<Option<&[u8]>, ProtocolError> {
    if value.is_empty() {
        return Ok(None);
    }
    if !value.starts_with(b"a=") {
        return Err(ProtocolError::MalformedMessage);
    }
    validate_identity(&value[2..], maximum)?;
    Ok(Some(&value[2..]))
}
