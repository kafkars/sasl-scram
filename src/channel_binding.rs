//! Caller-supplied channel-binding names, bytes, and negotiation mode.

use alloc::boxed::Box;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PolicyError, ResourceLimits, SecretBytes};

const MAX_CHANNEL_BINDING_NAME_BYTES: usize = 128;

/// A validated GS2 channel-binding name.
#[derive(Clone, Eq, PartialEq)]
pub struct ChannelBindingName(Box<str>);

impl ChannelBindingName {
    /// Validates and owns a channel-binding name.
    pub fn new(name: impl Into<Box<str>>) -> Result<Self, PolicyError> {
        let name = name.into();
        if !is_valid_channel_binding_name(name.as_bytes()) {
            return Err(PolicyError::InvalidChannelBindingName);
        }
        Ok(Self(name))
    }

    /// Borrows the validated channel-binding name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Zeroize for ChannelBindingName {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ChannelBindingName {}

impl Drop for ChannelBindingName {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ChannelBindingName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ChannelBindingName")
            .field(&self.0)
            .finish()
    }
}

/// Owned channel-binding bytes, redacted and zeroized like other key material.
pub struct ChannelBindingData(SecretBytes);

impl ChannelBindingData {
    /// Takes ownership of caller-extracted channel-binding bytes.
    pub fn new(data: SecretBytes) -> Self {
        Self(data)
    }

    /// Explicitly borrows the channel-binding bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the binding-data length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the binding data is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Zeroize for ChannelBindingData {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ChannelBindingData {}

impl fmt::Debug for ChannelBindingData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBindingData")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// One validated channel-binding name and payload supplied by the transport.
pub struct ChannelBinding {
    name: ChannelBindingName,
    data: ChannelBindingData,
}

impl ChannelBinding {
    /// Creates binding data within the configured decoded-payload limit.
    pub fn new(
        name: ChannelBindingName,
        data: ChannelBindingData,
        limits: &ResourceLimits,
    ) -> Result<Self, PolicyError> {
        if data.is_empty() {
            return Err(PolicyError::ChannelBindingRequired);
        }
        if data.len() > limits.max_channel_binding_bytes() {
            return Err(PolicyError::ChannelBindingTooLarge {
                length: data.len(),
                maximum: limits.max_channel_binding_bytes(),
            });
        }
        Ok(Self { name, data })
    }

    /// Returns the validated binding name.
    pub const fn name(&self) -> &ChannelBindingName {
        &self.name
    }

    /// Explicitly returns the binding payload.
    pub const fn data(&self) -> &ChannelBindingData {
        &self.data
    }
}

impl Zeroize for ChannelBinding {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for ChannelBinding {}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBinding")
            .field("name", &self.name)
            .field("data", &self.data)
            .finish()
    }
}

/// The negotiated GS2 channel-binding mode.
#[non_exhaustive]
pub enum ChannelBindingMode {
    /// Channel binding is unavailable; clients emit `n` and servers are unbound.
    Unsupported,
    /// Binding is supported but the non-PLUS mechanism was negotiated.
    ///
    /// Clients emit `y`. Servers reject peer `y` as downgrade evidence while
    /// still permitting `n` from clients that do not support channel binding.
    AvailableButNotNegotiated,
    /// Select PLUS, emit or require `p=<name>`, and authenticate the supplied data.
    Required(ChannelBinding),
}

impl fmt::Debug for ChannelBindingMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("Unsupported"),
            Self::AvailableButNotNegotiated => formatter.write_str("AvailableButNotNegotiated"),
            Self::Required(_) => formatter
                .debug_struct("Required")
                .field("contents", &"[REDACTED]")
                .finish(),
        }
    }
}

impl Zeroize for ChannelBindingMode {
    fn zeroize(&mut self) {
        if let Self::Required(binding) = self {
            binding.zeroize();
        }
    }
}

impl ZeroizeOnDrop for ChannelBindingMode {}

pub(crate) fn is_valid_channel_binding_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_CHANNEL_BINDING_NAME_BYTES {
        return false;
    }
    name.iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}
