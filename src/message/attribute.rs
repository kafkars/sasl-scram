//! Single-pass attribute scanning and shared structural validation.

use core::str;

use crate::{AttributeName, ProtocolError, ResourceLimits};

pub(super) struct Attribute<'a> {
    pub(super) name: u8,
    pub(super) value: &'a [u8],
    pub(super) start: usize,
    pub(super) end: usize,
}

pub(super) struct AttributeScanner<'a> {
    input: &'a [u8],
    cursor: usize,
    count: usize,
    seen_reserved: u16,
    maximum_attributes: usize,
}

impl<'a> AttributeScanner<'a> {
    pub(super) fn new(input: &'a [u8], limits: &ResourceLimits) -> Result<Self, ProtocolError> {
        ensure_message_limit(input, limits)?;
        if input.is_empty() {
            return Err(ProtocolError::MalformedMessage);
        }
        Ok(Self {
            input,
            cursor: 0,
            count: 0,
            seen_reserved: 0,
            maximum_attributes: limits.max_attributes(),
        })
    }

    pub(super) fn next(&mut self) -> Result<Option<Attribute<'a>>, ProtocolError> {
        if self.cursor == self.input.len() {
            return Ok(None);
        }
        if self.count == self.maximum_attributes {
            return Err(ProtocolError::TooManyAttributes {
                maximum: self.maximum_attributes,
            });
        }
        let start = self.cursor;
        let remaining = &self.input[start..];
        let relative_end = remaining
            .iter()
            .position(|byte| *byte == b',')
            .unwrap_or(remaining.len());
        let end = start + relative_end;
        if end == start || end - start < 2 || self.input[start + 1] != b'=' {
            return Err(ProtocolError::MalformedMessage);
        }
        if !self.input[start].is_ascii_alphabetic() {
            return Err(ProtocolError::MalformedMessage);
        }
        if end < self.input.len() {
            if end + 1 == self.input.len() {
                return Err(ProtocolError::MalformedMessage);
            }
            self.cursor = end + 1;
        } else {
            self.cursor = end;
        }
        self.count += 1;
        let name = self.input[start];
        self.record_reserved(name)?;
        Ok(Some(Attribute {
            name,
            value: &self.input[start + 2..end],
            start,
            end,
        }))
    }

    fn record_reserved(&mut self, name: u8) -> Result<(), ProtocolError> {
        let Some(reserved) = AttributeName::from_byte(name) else {
            return Ok(());
        };
        let bit = 1_u16 << reserved_bit(reserved);
        if self.seen_reserved & bit != 0 {
            return Err(ProtocolError::DuplicateAttribute(reserved));
        }
        self.seen_reserved |= bit;
        Ok(())
    }
}

const fn reserved_bit(name: AttributeName) -> u8 {
    match name {
        AttributeName::AuthorizationIdentity => 0,
        AttributeName::ChannelBinding => 1,
        AttributeName::ServerError => 2,
        AttributeName::IterationCount => 3,
        AttributeName::MandatoryExtension => 4,
        AttributeName::AuthenticationIdentity => 5,
        AttributeName::Proof => 6,
        AttributeName::Nonce => 7,
        AttributeName::Salt => 8,
        AttributeName::Verifier => 9,
    }
}

pub(super) fn expect<'a>(
    scanner: &mut AttributeScanner<'a>,
    expected: AttributeName,
) -> Result<Attribute<'a>, ProtocolError> {
    let Some(attribute) = scanner.next()? else {
        return Err(ProtocolError::MissingAttribute(expected));
    };
    if attribute.name == b'm' {
        return Err(ProtocolError::UnsupportedMandatoryExtension);
    }
    if attribute.name != expected.as_byte() {
        return Err(ProtocolError::InvalidAttributeOrder);
    }
    Ok(attribute)
}

pub(super) fn ensure_message_limit(
    input: &[u8],
    limits: &ResourceLimits,
) -> Result<(), ProtocolError> {
    if input.len() > limits.max_message_bytes() {
        return Err(ProtocolError::MessageTooLarge {
            length: input.len(),
            maximum: limits.max_message_bytes(),
        });
    }
    Ok(())
}

pub(super) fn validate_identity(value: &[u8], maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || str::from_utf8(value).is_err() {
        return Err(ProtocolError::InvalidIdentityEscape);
    }
    let mut index = 0;
    let mut decoded_length = 0;
    while index < value.len() {
        if value[index] == 0 {
            return Err(ProtocolError::InvalidIdentityEscape);
        }
        if value[index] == b'=' {
            if index + 2 >= value.len() || !matches!(&value[index..index + 3], b"=2C" | b"=3D") {
                return Err(ProtocolError::InvalidIdentityEscape);
            }
            index += 3;
        } else {
            index += 1;
        }
        decoded_length += 1;
        if decoded_length > maximum {
            return Err(ProtocolError::InvalidIdentityEscape);
        }
    }
    Ok(())
}

pub(super) fn validate_value(value: &[u8]) -> Result<(), ProtocolError> {
    if value.is_empty() || value.contains(&0) || str::from_utf8(value).is_err() {
        return Err(ProtocolError::MalformedMessage);
    }
    Ok(())
}

pub(super) fn validate_nonce(value: &[u8], maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b',')
    {
        return Err(ProtocolError::InvalidNonce);
    }
    Ok(())
}
