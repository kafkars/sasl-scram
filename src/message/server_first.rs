//! Parsing for the exact server-first transcript fragment.

use core::{fmt, num::NonZeroU32};

use crate::{AttributeName, IterationCount, ProtocolError, ResourceLimits};

use super::{
    attribute::{AttributeScanner, expect, validate_nonce},
    base64::validate_base64,
    extensions::{ExtensionTracker, Extensions},
};

/// A validated server-first message retaining its exact input.
pub struct ServerFirst<'a> {
    raw: &'a [u8],
    nonce: &'a [u8],
    salt_base64: &'a [u8],
    salt_length: usize,
    iterations: IterationCount,
    extensions: Extensions<'a>,
}

impl<'a> ServerFirst<'a> {
    /// Parses one bounded server-first message without allocating.
    pub fn parse(input: &'a [u8], limits: &ResourceLimits) -> Result<Self, ProtocolError> {
        let mut scanner = AttributeScanner::new(input, limits)?;
        let nonce = expect(&mut scanner, AttributeName::Nonce)?;
        validate_nonce(nonce.value, limits.max_nonce_bytes())?;
        let salt = expect(&mut scanner, AttributeName::Salt)?;
        let salt_length = validate_base64(salt.value)?;
        if salt_length > limits.max_salt_bytes() {
            return Err(ProtocolError::SaltTooLarge {
                length: salt_length,
                maximum: limits.max_salt_bytes(),
            });
        }
        let iterations = expect(&mut scanner, AttributeName::IterationCount)?;
        let iterations = parse_iterations(iterations.value)?;
        let mut tracker = ExtensionTracker::new();
        while let Some(attribute) = scanner.next()? {
            tracker.push(&attribute, limits)?;
        }
        Ok(Self {
            raw: input,
            nonce: nonce.value,
            salt_base64: salt.value,
            salt_length,
            iterations,
            extensions: tracker.finish(input),
        })
    }

    /// Returns the complete server-first transcript fragment exactly as received.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Returns the combined nonce.
    pub const fn nonce(&self) -> &'a [u8] {
        self.nonce
    }

    /// Returns the validated canonical Base64 salt without decoding it.
    pub const fn salt_base64(&self) -> &'a [u8] {
        self.salt_base64
    }

    /// Returns the decoded salt length without allocating decoded bytes.
    pub const fn salt_length(&self) -> usize {
        self.salt_length
    }

    /// Returns the positive iteration count.
    pub const fn iterations(&self) -> IterationCount {
        self.iterations
    }

    /// Returns preserved unknown optional extensions.
    pub const fn extensions(&self) -> Extensions<'a> {
        self.extensions
    }
}

impl fmt::Debug for ServerFirst<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerFirst")
            .field("length", &self.raw.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn parse_iterations(value: &[u8]) -> Result<IterationCount, ProtocolError> {
    if value.is_empty() || value[0] == b'0' || !value.iter().all(u8::is_ascii_digit) {
        return Err(ProtocolError::InvalidIterationCount);
    }
    let mut count = 0_u32;
    for digit in value {
        let Some(next) = count
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(*digit - b'0')))
        else {
            return Err(ProtocolError::InvalidIterationCount);
        };
        count = next;
    }
    let Some(count) = NonZeroU32::new(count) else {
        return Err(ProtocolError::InvalidIterationCount);
    };
    Ok(IterationCount::new(count))
}
