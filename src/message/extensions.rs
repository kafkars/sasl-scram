//! Exact preservation and bounds for unknown optional extensions.

use core::fmt;

use crate::{AttributeName, ProtocolError, ResourceLimits};

use super::attribute::{Attribute, validate_value};

/// Unknown optional extensions preserved exactly as received.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Extensions<'a> {
    raw: &'a [u8],
    count: usize,
}

impl<'a> Extensions<'a> {
    /// Returns the exact comma-separated extension bytes without a leading comma.
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// Returns the number of optional attributes.
    pub const fn len(self) -> usize {
        self.count
    }

    /// Reports whether there were no optional extensions.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }
}

impl fmt::Debug for Extensions<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Extensions")
            .field("length", &self.raw.len())
            .field("count", &self.count)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

pub(super) struct ExtensionTracker {
    start: Option<usize>,
    end: usize,
    count: usize,
}

impl ExtensionTracker {
    pub(super) const fn new() -> Self {
        Self {
            start: None,
            end: 0,
            count: 0,
        }
    }

    pub(super) fn push(
        &mut self,
        attribute: &Attribute<'_>,
        limits: &ResourceLimits,
    ) -> Result<(), ProtocolError> {
        validate_value(attribute.value)?;
        if attribute.name == b'm' {
            return Err(ProtocolError::UnsupportedMandatoryExtension);
        }
        if let Some(name) = AttributeName::from_byte(attribute.name) {
            return Err(ProtocolError::UnexpectedAttribute(name));
        }
        let start = *self.start.get_or_insert(attribute.start);
        let length = attribute.end - start;
        if length > limits.max_extension_bytes() {
            return Err(ProtocolError::ExtensionsTooLarge {
                length,
                maximum: limits.max_extension_bytes(),
            });
        }
        self.end = attribute.end;
        self.count += 1;
        Ok(())
    }

    pub(super) fn finish<'a>(&self, input: &'a [u8]) -> Extensions<'a> {
        let raw = self
            .start
            .map_or(&input[0..0], |start| &input[start..self.end]);
        Extensions {
            raw,
            count: self.count,
        }
    }
}
