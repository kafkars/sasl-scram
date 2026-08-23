//! Canonical outbound-message and transcript assembly coverage.

use core::num::NonZeroU32;

use sasl_scram::{
    ChannelBinding, ChannelBindingData, ChannelBindingMode, ChannelBindingName, IterationCount,
    PeerError, PolicyError, PreparedAuthenticationIdentity, PreparedAuthorizationIdentity,
    ProtocolError, ResourceLimits, SecretBytes,
    message::{
        AuthenticationTranscript, ClientFinal, ClientFirst, ServerFinal, ServerFirst,
        encode_client_final, encode_client_final_without_proof, encode_client_first,
        encode_server_final_error, encode_server_final_verifier, encode_server_first,
    },
};

#[test]
fn canonical_messages_round_trip_through_borrowed_views() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::default();
    let identity = PreparedAuthenticationIdentity::from_protocol_profile("user")?;
    let mode = ChannelBindingMode::Unsupported;
    let client_first = encode_client_first(&mode, &identity, None, b"clientnonce", &limits)?;
    let server_first = encode_server_first(
        b"clientnonceSERVER",
        b"salt",
        IterationCount::new(NonZeroU32::MIN.saturating_add(4095)),
        &limits,
    )?;
    let client_final = encode_client_final(&mode, None, b"clientnonceSERVER", b"proof", &limits)?;
    let pending_final =
        encode_client_final_without_proof(&mode, None, b"clientnonceSERVER", &limits)?;
    let server_final = encode_server_final_verifier(b"verifier", &limits)?;

    assert_eq!(client_first.as_bytes(), b"n,,n=user,r=clientnonce");
    assert_eq!(
        server_first.as_bytes(),
        b"r=clientnonceSERVER,s=c2FsdA==,i=4096"
    );
    assert_eq!(
        client_final.as_bytes(),
        b"c=biws,r=clientnonceSERVER,p=cHJvb2Y="
    );
    assert_eq!(pending_final.as_bytes(), b"c=biws,r=clientnonceSERVER");
    assert_eq!(
        pending_final.finish(b"proof", &limits)?.as_bytes(),
        client_final.as_bytes()
    );
    assert_eq!(server_final.as_bytes(), b"v=dmVyaWZpZXI=");
    ClientFirst::parse(client_first.as_bytes(), &limits)?;
    ServerFirst::parse(server_first.as_bytes(), &limits)?;
    ClientFinal::parse(client_final.as_bytes(), &limits)?;
    ServerFinal::parse(server_final.as_bytes(), &limits)?;
    Ok(())
}

#[test]
fn plus_encoding_uses_exact_escaped_gs2_header_and_binding_data() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::default();
    let identity = PreparedAuthenticationIdentity::from_protocol_profile("user,=name")?;
    let authorization = PreparedAuthorizationIdentity::from_protocol_profile("act,=as")?;
    let binding = ChannelBinding::new(
        ChannelBindingName::new("1-example")?,
        ChannelBindingData::new(SecretBytes::new([0_u8, 1_u8].as_slice())),
        &limits,
    )?;
    let mode = ChannelBindingMode::Required(binding);
    let first = encode_client_first(&mode, &identity, Some(&authorization), b"nonce", &limits)?;
    let final_message =
        encode_client_final(&mode, Some(&authorization), b"nonceSERVER", b"", &limits)?;

    assert_eq!(
        first.as_bytes(),
        b"p=1-example,a=act=2C=3Das,n=user=2C=3Dname,r=nonce"
    );
    let parsed_first = ClientFirst::parse(first.as_bytes(), &limits)?;
    assert_eq!(
        parsed_first.decode_authorization_identity()?.as_deref(),
        Some("act,=as")
    );
    assert_eq!(
        final_message.as_bytes(),
        b"c=cD0xLWV4YW1wbGUsYT1hY3Q9MkM9M0RhcywAAQ==,r=nonceSERVER,p="
    );
    Ok(())
}

#[test]
fn base64_and_decimal_encoders_cover_their_complete_structural_domains()
-> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::default();
    for length in 0_u8..=64 {
        let verifier = (0..length).collect::<Vec<_>>();
        let encoded = encode_server_final_verifier(&verifier, &limits)?;
        ServerFinal::parse(encoded.as_bytes(), &limits)?;
    }
    let maximum = IterationCount::new(NonZeroU32::MAX);
    let encoded = encode_server_first(b"nonce", b"", maximum, &limits)?;
    let parsed = ServerFirst::parse(encoded.as_bytes(), &limits)?;

    assert_eq!(parsed.iterations(), maximum);
    assert_eq!(encoded.as_bytes(), b"r=nonce,s=,i=4294967295");
    Ok(())
}

#[test]
fn transcript_is_exact_and_all_diagnostics_are_redacted() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::default();
    let first_wire = b"n,,n=user,r=client";
    let server_wire = b"r=clientSERVER,s=c2FsdA==,i=4096,x=kept";
    let final_wire = b"c=biws,r=clientSERVER,z=kept,p=cHJvb2Y=";
    let first = ClientFirst::parse(first_wire, &limits)?;
    let server = ServerFirst::parse(server_wire, &limits)?;
    let final_message = ClientFinal::parse(final_wire, &limits)?;
    let transcript = AuthenticationTranscript::from_messages(&first, &server, &final_message);
    let owned = transcript.to_owned_message(&limits)?;

    assert_eq!(
        owned.as_bytes(),
        b"n=user,r=client,r=clientSERVER,s=c2FsdA==,i=4096,x=kept,c=biws,r=clientSERVER,z=kept"
    );
    assert!(!format!("{transcript:?}").contains("clientSERVER"));
    assert!(!format!("{owned:?}").contains("clientSERVER"));
    assert!(format!("{owned:?}").contains("[REDACTED]"));
    Ok(())
}

#[test]
fn outbound_transfer_and_errors_remain_explicit_and_bounded() -> Result<(), sasl_scram::Error> {
    let limits = ResourceLimits::default();
    let message = encode_server_final_error(PeerError::Other, &limits)?;
    let bytes = message.into_exposed_bytes();
    let tiny = ResourceLimits::builder()
        .max_message_bytes(120)
        .max_channel_binding_bytes(1)
        .build()?;
    let identity_text = "u".repeat(120);
    let identity = PreparedAuthenticationIdentity::from_protocol_profile(identity_text)?;
    let oversized = encode_client_first(
        &ChannelBindingMode::Unsupported,
        &identity,
        None,
        b"nonce",
        &tiny,
    );

    assert_eq!(&*bytes, b"e=other-error");
    assert!(matches!(
        oversized,
        Err(ProtocolError::MessageTooLarge {
            length: 133,
            maximum: 120
        })
    ));
    Ok(())
}

#[test]
fn binding_limits_must_fit_inside_a_complete_message() {
    assert_eq!(
        ResourceLimits::default().max_channel_binding_bytes(),
        8 * 1024
    );
    assert_eq!(
        ResourceLimits::builder()
            .max_channel_binding_bytes(16 * 1024)
            .build(),
        Err(PolicyError::InvalidResourceLimit)
    );
}
