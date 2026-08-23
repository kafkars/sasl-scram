//! Small owned secret wrappers that do not leak third-party types.

use alloc::{boxed::Box, string::String};
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owned secret bytes that are zeroized on drop.
///
/// Secret owners cannot be cloned, displayed, or compared with ordinary
/// variable-time equality:
///
/// ```compile_fail
/// fn clone_secret(secret: &sasl_scram::SecretBytes) {
///     let _copy = Clone::clone(secret);
/// }
/// ```
///
/// ```compile_fail
/// fn display_secret(secret: &sasl_scram::SecretBytes) {
///     let _text = format!("{secret}");
/// }
/// ```
///
/// ```compile_fail
/// fn compare_secret(left: &sasl_scram::SecretBytes, right: &sasl_scram::SecretBytes) {
///     let _same = left == right;
/// }
/// ```
pub struct SecretBytes {
    bytes: Zeroizing<Box<[u8]>>,
}

impl SecretBytes {
    /// Takes ownership of bytes as secret material.
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    /// Explicitly borrows the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Owned UTF-8 secret text that is zeroized on drop.
pub struct SecretString {
    text: Zeroizing<String>,
}

impl SecretString {
    /// Takes ownership of text as secret material.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: Zeroizing::new(text.into()),
        }
    }

    /// Explicitly borrows the secret text.
    pub fn expose_secret(&self) -> &str {
        &self.text
    }

    /// Returns the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Reports whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Transfers the value into secret bytes while zeroizing the original string allocation.
    pub fn into_secret_bytes(self) -> SecretBytes {
        SecretBytes::new(self.text.as_bytes())
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.text.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretString")
            .field("length", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
