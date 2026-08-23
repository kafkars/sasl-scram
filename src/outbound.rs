//! Opaque, redacted ownership for complete outbound SCRAM messages.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An owned SCRAM message whose contents are explicit to access and zeroized on drop.
///
/// The type deliberately has no `Clone` or `Display` implementation:
///
/// ```compile_fail
/// use sasl_scram::{PeerError, ResourceLimits, message::encode_server_final_error};
///
/// let Ok(message) = encode_server_final_error(PeerError::Other, &ResourceLimits::default())
/// else {
///     return;
/// };
/// let _copy = Clone::clone(&message);
/// ```
///
/// ```compile_fail
/// use sasl_scram::{PeerError, ResourceLimits, message::encode_server_final_error};
///
/// let Ok(message) = encode_server_final_error(PeerError::Other, &ResourceLimits::default())
/// else {
///     return;
/// };
/// let _text = format!("{message}");
/// ```
pub struct OutboundMessage {
    bytes: Zeroizing<Box<[u8]>>,
}

impl OutboundMessage {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.into_boxed_slice()),
        }
    }

    /// Explicitly borrows the bytes to pass to an application transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies the bytes into an ordinary caller-owned allocation.
    ///
    /// The crate-owned allocation is zeroized as `self` is consumed, but the
    /// returned allocation is unprotected and becomes the caller's explicit
    /// responsibility. Prefer [`Self::as_bytes`] when the transport can borrow.
    pub fn into_exposed_bytes(self) -> Box<[u8]> {
        self.bytes.to_vec().into_boxed_slice()
    }

    /// Returns the message length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the message contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Zeroize for OutboundMessage {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for OutboundMessage {}

impl fmt::Debug for OutboundMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundMessage")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
