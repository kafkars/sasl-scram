//! Fail-closed parser regression cases for hostile peer input.

use sasl_scram::{
    AttributeName, ProtocolError, ResourceLimits,
    message::{ClientFinal, ClientFirst, ServerFinal, ServerFirst},
};

#[test]
fn reserved_duplicates_are_rejected() {
    let result = ServerFirst::parse(
        b"r=nonce,s=QSXCR+Q6sek8bf92,i=4096,r=again",
        &ResourceLimits::default(),
    );

    assert_eq!(
        result.err(),
        Some(ProtocolError::DuplicateAttribute(AttributeName::Nonce))
    );
}

#[test]
fn unsupported_mandatory_extensions_fail_in_every_extension_position() {
    let first = ClientFirst::parse(b"n,,m=required,n=user,r=nonce", &ResourceLimits::default());
    let later = ServerFirst::parse(
        b"r=nonce,s=QSXCR+Q6sek8bf92,i=4096,m=required",
        &ResourceLimits::default(),
    );

    assert_eq!(
        first.err(),
        Some(ProtocolError::UnsupportedMandatoryExtension)
    );
    assert_eq!(
        later.err(),
        Some(ProtocolError::UnsupportedMandatoryExtension)
    );
}

#[test]
fn noncanonical_base64_is_rejected() {
    let bad_padding = ServerFirst::parse(b"r=nonce,s=Zh==,i=4096", &ResourceLimits::default());
    let missing_padding =
        ClientFinal::parse(b"c=biws,r=nonce,p=dGVzdA", &ResourceLimits::default());

    assert_eq!(bad_padding.err(), Some(ProtocolError::InvalidBase64));
    assert_eq!(missing_padding.err(), Some(ProtocolError::InvalidBase64));
}

#[test]
fn malformed_identity_escapes_are_rejected() {
    let lowercase_escape =
        ClientFirst::parse(b"n,,n=user=2cname,r=nonce", &ResourceLimits::default());
    let truncated_escape = ClientFirst::parse(b"n,,n=user=,r=nonce", &ResourceLimits::default());

    assert_eq!(
        lowercase_escape.err(),
        Some(ProtocolError::InvalidIdentityEscape)
    );
    assert_eq!(
        truncated_escape.err(),
        Some(ProtocolError::InvalidIdentityEscape)
    );
}

#[test]
fn nonce_size_and_syntax_failures_remain_distinct() -> Result<(), sasl_scram::PolicyError> {
    let limits = ResourceLimits::builder().max_nonce_bytes(4).build()?;
    let oversized = ServerFirst::parse(b"r=nonce,s=,i=4096", &limits);
    let malformed = ServerFirst::parse(b"r=no e,s=,i=4096", &limits);

    assert_eq!(
        oversized.err(),
        Some(ProtocolError::NonceTooLarge {
            length: 5,
            maximum: 4,
        })
    );
    assert_eq!(malformed.err(), Some(ProtocolError::InvalidNonce));
    Ok(())
}

#[test]
fn nul_identities_and_empty_extension_values_are_rejected() {
    let nul = ClientFirst::parse(b"n,,n=user\0name,r=nonce", &ResourceLimits::default());
    let empty_extension = ServerFirst::parse(
        b"r=nonce,s=QSXCR+Q6sek8bf92,i=4096,x=",
        &ResourceLimits::default(),
    );

    assert_eq!(nul.err(), Some(ProtocolError::InvalidIdentityEscape));
    assert_eq!(empty_extension.err(), Some(ProtocolError::MalformedMessage));
}

#[test]
fn extension_and_peer_error_values_must_be_valid_utf8_without_nul() {
    let invalid_utf8 = ServerFirst::parse(
        b"r=nonce,s=QSXCR+Q6sek8bf92,i=4096,x=\xff",
        &ResourceLimits::default(),
    );
    let nul_extension = ServerFirst::parse(
        b"r=nonce,s=QSXCR+Q6sek8bf92,i=4096,x=a\0b",
        &ResourceLimits::default(),
    );
    let invalid_peer_error = ServerFinal::parse(b"e=vendor\xff", &ResourceLimits::default());

    assert_eq!(invalid_utf8.err(), Some(ProtocolError::MalformedMessage));
    assert_eq!(nul_extension.err(), Some(ProtocolError::MalformedMessage));
    assert_eq!(
        invalid_peer_error.err(),
        Some(ProtocolError::MalformedMessage)
    );
}

#[test]
fn optional_extension_values_follow_the_complete_value_char_abnf()
-> Result<(), sasl_scram::ProtocolError> {
    let control = ServerFirst::parse(b"r=nonce,s=,i=4096,x=\x01", &ResourceLimits::default())?;
    let delete = ServerFirst::parse(b"r=nonce,s=,i=4096,X=\x7f", &ResourceLimits::default())?;

    assert_eq!(control.extensions().raw(), b"x=\x01");
    assert_eq!(delete.extensions().raw(), b"X=\x7f");
    Ok(())
}

#[test]
fn channel_binding_names_reject_only_values_outside_the_bounded_gs2_abnf() {
    let empty = ClientFirst::parse(b"p=,,n=user,r=nonce", &ResourceLimits::default());
    let underscore = ClientFirst::parse(b"p=tls_bad,,n=user,r=nonce", &ResourceLimits::default());
    let non_ascii = ClientFirst::parse(
        b"p=tls-\xc3\xa9,,n=user,r=nonce",
        &ResourceLimits::default(),
    );

    assert_eq!(empty.err(), Some(ProtocolError::InvalidChannelBindingName));
    assert_eq!(
        underscore.err(),
        Some(ProtocolError::InvalidChannelBindingName)
    );
    assert_eq!(
        non_ascii.err(),
        Some(ProtocolError::InvalidChannelBindingName)
    );
}

#[test]
fn identity_limits_count_decoded_bytes_after_scram_escaping() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::builder().max_identity_bytes(1).build()?;
    let accepted = ClientFirst::parse(b"n,,n==2C,r=nonce", &limits)?;
    let rejected = ClientFirst::parse(b"n,,n==2C=3D,r=nonce", &limits);

    assert_eq!(accepted.decode_authentication_identity()?.as_ref(), ",");
    assert_eq!(rejected.err(), Some(ProtocolError::InvalidIdentityEscape));
    Ok(())
}

#[test]
fn structurally_empty_base64_is_left_for_state_validation() -> Result<(), sasl_scram::ProtocolError>
{
    let server_first = ServerFirst::parse(b"r=nonce,s=,i=4096", &ResourceLimits::default())?;
    let client_final = ClientFinal::parse(b"c=,r=nonce,p=", &ResourceLimits::default())?;
    let server_final = ServerFinal::parse(b"v=", &ResourceLimits::default())?;

    assert_eq!(server_first.salt_base64(), b"");
    assert_eq!(client_final.channel_binding_base64(), b"");
    assert_eq!(client_final.proof_base64(), b"");
    assert!(matches!(
        server_final.outcome(),
        sasl_scram::message::ServerFinalOutcome::Verified(value)
            if value.expose_base64().is_empty()
    ));
    Ok(())
}

#[test]
fn channel_binding_payload_policy_is_left_for_state_validation() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::builder()
        .max_channel_binding_bytes(1)
        .build()?;
    let parsed = ClientFinal::parse(b"c=biws,r=nonce,p=", &limits)?;

    assert_eq!(parsed.channel_binding_base64(), b"biws");
    Ok(())
}

#[test]
fn required_attribute_order_is_not_reconstructed() {
    let result = ServerFirst::parse(
        b"s=QSXCR+Q6sek8bf92,r=nonce,i=4096",
        &ResourceLimits::default(),
    );

    assert_eq!(result.err(), Some(ProtocolError::InvalidAttributeOrder));
}

#[test]
fn server_final_must_contain_exactly_one_terminal_attribute() {
    let both = ServerFinal::parse(b"v=dGVzdA==,e=invalid-proof", &ResourceLimits::default());
    let neither = ServerFinal::parse(b"x=optional", &ResourceLimits::default());

    assert_eq!(
        both.err(),
        Some(ProtocolError::UnexpectedAttribute(
            AttributeName::ServerError
        ))
    );
    assert_eq!(neither.err(), Some(ProtocolError::InvalidAttributeOrder));
}

#[test]
fn proof_must_be_the_last_client_final_attribute() {
    let result = ClientFinal::parse(
        b"c=biws,r=nonce,p=dGVzdA==,x=late",
        &ResourceLimits::default(),
    );

    assert_eq!(result.err(), Some(ProtocolError::InvalidAttributeOrder));
}

#[test]
fn message_and_attribute_limits_apply_before_unbounded_work() -> Result<(), sasl_scram::PolicyError>
{
    let limits = ResourceLimits::builder()
        .max_message_bytes(120)
        .max_attributes(2)
        .max_channel_binding_bytes(1)
        .build()?;
    let oversized_input = [b'x'; 121];
    let oversized = ServerFirst::parse(&oversized_input, &limits);
    let limits = ResourceLimits::builder().max_attributes(2).build()?;
    let too_many = ServerFirst::parse(b"r=n,s=AAAA,i=4096", &limits);

    assert_eq!(
        oversized.err(),
        Some(ProtocolError::MessageTooLarge {
            length: 121,
            maximum: 120,
        })
    );
    assert_eq!(
        too_many.err(),
        Some(ProtocolError::TooManyAttributes { maximum: 2 })
    );
    Ok(())
}
