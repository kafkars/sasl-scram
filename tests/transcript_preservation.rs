//! Exact-fragment tests for all four borrowed parser views.

use sasl_scram::{
    ResourceLimits,
    message::{ClientFinal, ClientFirst, Gs2Flag, ServerFinal, ServerFinalOutcome, ServerFirst},
};

#[test]
fn client_first_preserves_gs2_and_bare_fragments() -> Result<(), sasl_scram::ProtocolError> {
    let wire = b"n,,n=user=2Cname,r=clientnonce,x=one";
    let parsed = ClientFirst::parse(wire, &ResourceLimits::default())?;

    assert_eq!(parsed.raw(), wire);
    assert_eq!(parsed.gs2_header(), b"n,,");
    assert_eq!(parsed.bare(), b"n=user=2Cname,r=clientnonce,x=one");
    assert_eq!(parsed.authentication_identity(), b"user=2Cname");
    assert_eq!(parsed.nonce(), b"clientnonce");
    assert_eq!(parsed.channel_binding_flag(), Gs2Flag::Unsupported);
    assert_eq!(parsed.extensions().raw(), b"x=one");
    Ok(())
}

#[test]
fn server_first_preserves_original_attribute_bytes() -> Result<(), sasl_scram::ProtocolError> {
    let wire = b"r=clientnonceSERVER,s=QSXCR+Q6sek8bf92,i=4096,z=kept";
    let parsed = ServerFirst::parse(wire, &ResourceLimits::default())?;

    assert_eq!(parsed.raw(), wire);
    assert_eq!(parsed.nonce(), b"clientnonceSERVER");
    assert_eq!(parsed.salt_base64(), b"QSXCR+Q6sek8bf92");
    assert_eq!(parsed.iterations().get(), 4096);
    assert_eq!(parsed.extensions().raw(), b"z=kept");
    Ok(())
}

#[test]
fn client_final_preserves_without_proof_fragment() -> Result<(), sasl_scram::ProtocolError> {
    let wire = b"c=biws,r=clientnonceSERVER,x=kept,p=dGVzdA==";
    let parsed = ClientFinal::parse(wire, &ResourceLimits::default())?;

    assert_eq!(parsed.raw(), wire);
    assert_eq!(parsed.without_proof(), b"c=biws,r=clientnonceSERVER,x=kept");
    assert_eq!(parsed.channel_binding_base64(), b"biws");
    assert_eq!(parsed.proof_base64(), b"dGVzdA==");
    assert_eq!(parsed.extensions().raw(), b"x=kept");
    Ok(())
}

#[test]
fn server_final_maps_unknown_peer_text_without_retaining_it()
-> Result<(), sasl_scram::ProtocolError> {
    let wire = b"e=vendor-private-error,x=kept";
    let parsed = ServerFinal::parse(wire, &ResourceLimits::default())?;

    assert_eq!(parsed.raw(), wire);
    assert!(matches!(
        parsed.outcome(),
        ServerFinalOutcome::Rejected(sasl_scram::PeerError::Other)
    ));
    assert_eq!(parsed.extensions().raw(), b"x=kept");
    assert!(!format!("{parsed:?}").contains("vendor-private-error"));
    Ok(())
}

#[test]
fn server_verifier_outcome_debug_is_redacted() -> Result<(), sasl_scram::ProtocolError> {
    let parsed = ServerFinal::parse(b"v=c2VydmVyLXNpZ25hdHVyZQ==", &ResourceLimits::default())?;
    let debug = format!("{:?}", parsed.outcome());

    assert!(!debug.contains("c2VydmVyLXNpZ25hdHVyZQ"));
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}
