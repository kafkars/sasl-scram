//! Canonical padded Base64 validation without allocating decoded output.

use alloc::vec::Vec;

use crate::ProtocolError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(super) fn encoded_len(length: usize) -> Option<usize> {
    length.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

pub(super) fn append_encoded(output: &mut Vec<u8>, value: &[u8]) {
    let mut chunks = value.chunks_exact(3);
    for chunk in &mut chunks {
        output.push(ALPHABET[usize::from(chunk[0] >> 2)]);
        output.push(ALPHABET[usize::from((chunk[0] & 0x03) << 4 | chunk[1] >> 4)]);
        output.push(ALPHABET[usize::from((chunk[1] & 0x0f) << 2 | chunk[2] >> 6)]);
        output.push(ALPHABET[usize::from(chunk[2] & 0x3f)]);
    }
    match chunks.remainder() {
        [first] => {
            output.push(ALPHABET[usize::from(first >> 2)]);
            output.push(ALPHABET[usize::from((first & 0x03) << 4)]);
            output.extend_from_slice(b"==");
        }
        [first, second] => {
            output.push(ALPHABET[usize::from(first >> 2)]);
            output.push(ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)]);
            output.push(ALPHABET[usize::from((second & 0x0f) << 2)]);
            output.push(b'=');
        }
        _ => {}
    }
}

#[cfg(any(feature = "sha256", feature = "sha512"))]
pub(crate) fn encode_owned(value: &[u8]) -> Vec<u8> {
    let capacity = encoded_len(value.len()).unwrap_or(0);
    let mut output = Vec::with_capacity(capacity);
    append_encoded(&mut output, value);
    output
}

#[cfg(any(feature = "sha256", feature = "sha512"))]
pub(crate) fn decode_owned(value: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let length = validate_base64(value)?;
    let mut output = Vec::with_capacity(length);
    for chunk in value.chunks_exact(4) {
        let first = decode_required(chunk[0])?;
        let second = decode_required(chunk[1])?;
        output.push(first << 2 | second >> 4);
        if chunk[2] != b'=' {
            let third = decode_required(chunk[2])?;
            output.push(second << 4 | third >> 2);
            if chunk[3] != b'=' {
                let fourth = decode_required(chunk[3])?;
                output.push(third << 6 | fourth);
            }
        }
    }
    if output.len() != length {
        return Err(ProtocolError::InvalidBase64);
    }
    Ok(output)
}

pub(super) fn validate_base64(value: &[u8]) -> Result<usize, ProtocolError> {
    if !value.len().is_multiple_of(4) {
        return Err(ProtocolError::InvalidBase64);
    }
    if value.is_empty() {
        return Ok(0);
    }
    let padding = value.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return Err(ProtocolError::InvalidBase64);
    }
    let data_length = value.len() - padding;
    if value[..data_length]
        .iter()
        .any(|byte| decode(*byte).is_none())
        || value[..data_length].contains(&b'=')
    {
        return Err(ProtocolError::InvalidBase64);
    }
    match padding {
        0 => {}
        1 => {
            let Some(last) = decode(value[data_length - 1]) else {
                return Err(ProtocolError::InvalidBase64);
            };
            if last & 0b0000_0011 != 0 {
                return Err(ProtocolError::InvalidBase64);
            }
        }
        2 => {
            let Some(last) = decode(value[data_length - 1]) else {
                return Err(ProtocolError::InvalidBase64);
            };
            if last & 0b0000_1111 != 0 {
                return Err(ProtocolError::InvalidBase64);
            }
        }
        _ => return Err(ProtocolError::InvalidBase64),
    }
    Ok(value.len() / 4 * 3 - padding)
}

const fn decode(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(any(feature = "sha256", feature = "sha512"))]
fn decode_required(byte: u8) -> Result<u8, ProtocolError> {
    decode(byte).ok_or(ProtocolError::InvalidBase64)
}
