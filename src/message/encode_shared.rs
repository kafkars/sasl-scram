//! Shared GS2 and allocation bounds for canonical message encoders.

use alloc::vec::Vec;

use crate::{ChannelBindingMode, PreparedAuthorizationIdentity, ProtocolError, ResourceLimits};

use super::identity::{append_escaped, escaped_len};

pub(super) fn validate_outbound_identity(value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
        return Err(ProtocolError::InvalidIdentityEscape);
    }
    Ok(())
}

pub(super) fn validate_outbound_authorization(
    value: Option<&PreparedAuthorizationIdentity>,
    limits: &ResourceLimits,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => {
            validate_outbound_identity(value.as_str(), limits.max_authorization_identity_bytes())
        }
        None => Ok(()),
    }
}

pub(super) fn gs2_header_len(
    mode: &ChannelBindingMode,
    authorization_identity: Option<&PreparedAuthorizationIdentity>,
) -> Result<usize, ProtocolError> {
    let flag = match mode {
        ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated => 1,
        ChannelBindingMode::Required(binding) => checked_sum(&[2, binding.name().as_str().len()]),
    };
    let authorization = authorization_identity.map_or(0, |identity| {
        checked_sum(&[2, escaped_len(identity.as_str()).unwrap_or(usize::MAX)])
    });
    let length = checked_sum(&[flag, 1, authorization, 1]);
    if length == usize::MAX {
        return Err(ProtocolError::MessageTooLarge {
            length,
            maximum: usize::MAX,
        });
    }
    Ok(length)
}

pub(super) fn append_gs2_header(
    output: &mut Vec<u8>,
    mode: &ChannelBindingMode,
    authorization_identity: Option<&PreparedAuthorizationIdentity>,
) {
    match mode {
        ChannelBindingMode::Unsupported => output.push(b'n'),
        ChannelBindingMode::AvailableButNotNegotiated => output.push(b'y'),
        ChannelBindingMode::Required(binding) => {
            output.extend_from_slice(b"p=");
            output.extend_from_slice(binding.name().as_str().as_bytes());
        }
    }
    output.push(b',');
    if let Some(identity) = authorization_identity {
        output.extend_from_slice(b"a=");
        append_escaped(output, identity.as_str());
    }
    output.push(b',');
}

pub(super) fn binding_data<'a>(
    mode: &'a ChannelBindingMode,
    limits: &ResourceLimits,
) -> Result<&'a [u8], ProtocolError> {
    let data = match mode {
        ChannelBindingMode::Required(binding) => binding.data().expose_secret(),
        ChannelBindingMode::Unsupported | ChannelBindingMode::AvailableButNotNegotiated => &[],
    };
    if data.len() > limits.max_channel_binding_bytes() {
        return Err(ProtocolError::ChannelBindingTooLarge {
            length: data.len(),
            maximum: limits.max_channel_binding_bytes(),
        });
    }
    Ok(data)
}

pub(super) fn bounded_output(
    length: usize,
    limits: &ResourceLimits,
) -> Result<Vec<u8>, ProtocolError> {
    if length == usize::MAX || length > limits.max_message_bytes() {
        return Err(ProtocolError::MessageTooLarge {
            length,
            maximum: limits.max_message_bytes(),
        });
    }
    Ok(Vec::with_capacity(length))
}

pub(super) fn checked_sum(values: &[usize]) -> usize {
    values
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(*value))
        .unwrap_or(usize::MAX)
}
