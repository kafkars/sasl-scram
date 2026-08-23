//! Cross-field capacity checks for complete client-final messages.

#[cfg(any(feature = "sha256", feature = "sha512"))]
use crate::PolicyError;

use super::ResourceLimits;

const MAX_SCRAM_OUTPUT_BYTES: usize = 64;
const MIN_CHANNEL_BINDING_NAME_BYTES: usize = 1;

pub(super) fn maximum_binding_fits(limits: ResourceLimits) -> bool {
    matches!(
        client_final_length(
            MIN_CHANNEL_BINDING_NAME_BYTES,
            limits.max_channel_binding_bytes(),
            0,
            false,
            1,
            MAX_SCRAM_OUTPUT_BYTES,
        ),
        Some(length) if length <= limits.max_message_bytes()
    )
}

impl ResourceLimits {
    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) fn validate_client_first_capacity(
        self,
        binding_name_bytes: usize,
        authentication_identity: &str,
        authorization_identity: Option<&str>,
        nonce_bytes: usize,
    ) -> Result<(), PolicyError> {
        let length = client_first_length(
            binding_name_bytes,
            authentication_identity,
            authorization_identity,
            nonce_bytes,
        );
        match length {
            Some(length) if length <= self.max_message_bytes() => Ok(()),
            Some(_) | None => Err(PolicyError::InvalidResourceLimit),
        }
    }

    #[cfg(any(feature = "sha256", feature = "sha512"))]
    pub(crate) fn validate_client_final_capacity(
        self,
        binding_name_bytes: usize,
        binding_data_bytes: usize,
        authorization_identity_bytes: usize,
        has_authorization_identity: bool,
        proof_bytes: usize,
    ) -> Result<(), PolicyError> {
        let length = client_final_length(
            binding_name_bytes,
            binding_data_bytes,
            authorization_identity_bytes,
            has_authorization_identity,
            self.max_nonce_bytes(),
            proof_bytes,
        );
        match length {
            Some(length) if length <= self.max_message_bytes() => Ok(()),
            Some(_) | None => Err(PolicyError::InvalidResourceLimit),
        }
    }
}

#[cfg(any(feature = "sha256", feature = "sha512"))]
fn client_first_length(
    binding_name_bytes: usize,
    authentication_identity: &str,
    authorization_identity: Option<&str>,
    nonce_bytes: usize,
) -> Option<usize> {
    let flag = if binding_name_bytes == 0 {
        1
    } else {
        2_usize.checked_add(binding_name_bytes)?
    };
    let authorization = match authorization_identity {
        Some(identity) => 2_usize.checked_add(escaped_identity_length(identity)?)?,
        None => 0,
    };
    flag.checked_add(authorization)?
        .checked_add(7)?
        .checked_add(escaped_identity_length(authentication_identity)?)?
        .checked_add(nonce_bytes)
}

#[cfg(any(feature = "sha256", feature = "sha512"))]
fn escaped_identity_length(value: &str) -> Option<usize> {
    value.as_bytes().iter().try_fold(0_usize, |length, byte| {
        length.checked_add(if matches!(byte, b',' | b'=') { 3 } else { 1 })
    })
}

fn client_final_length(
    binding_name_bytes: usize,
    binding_data_bytes: usize,
    authorization_identity_bytes: usize,
    has_authorization_identity: bool,
    nonce_bytes: usize,
    proof_bytes: usize,
) -> Option<usize> {
    let flag = if binding_name_bytes == 0 {
        1
    } else {
        2_usize.checked_add(binding_name_bytes)?
    };
    let authorization = if has_authorization_identity {
        let escaped = authorization_identity_bytes.checked_mul(3)?;
        2_usize.checked_add(escaped)?
    } else {
        0
    };
    let header = flag.checked_add(authorization)?.checked_add(2)?;
    let binding_input = header.checked_add(binding_data_bytes)?;
    let binding = base64_length(binding_input)?;
    let proof = base64_length(proof_bytes)?;
    8_usize
        .checked_add(binding)?
        .checked_add(nonce_bytes)?
        .checked_add(proof)
}

fn base64_length(bytes: usize) -> Option<usize> {
    bytes.checked_add(2)?.checked_div(3)?.checked_mul(4)
}
