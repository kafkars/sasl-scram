//! SCRAM identity escaping, decoding, and encoded-length accounting.

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::ProtocolError;

use super::attribute::validate_identity;

pub(super) fn escaped_len(value: &str) -> Option<usize> {
    value.as_bytes().iter().try_fold(0_usize, |length, byte| {
        length.checked_add(if matches!(byte, b',' | b'=') { 3 } else { 1 })
    })
}

pub(super) fn append_escaped(output: &mut Vec<u8>, value: &str) {
    for byte in value.as_bytes() {
        match byte {
            b',' => output.extend_from_slice(b"=2C"),
            b'=' => output.extend_from_slice(b"=3D"),
            _ => output.push(*byte),
        }
    }
}

pub(super) fn decode(value: &[u8], maximum: usize) -> Result<Box<str>, ProtocolError> {
    validate_identity(value, maximum)?;
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value.get(index..index + 3) {
            Some(b"=2C") => {
                decoded.push(b',');
                index += 3;
            }
            Some(b"=3D") => {
                decoded.push(b'=');
                index += 3;
            }
            _ => {
                decoded.push(value[index]);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded)
        .map(String::into_boxed_str)
        .map_err(|_| ProtocolError::InvalidIdentityEscape)
}
