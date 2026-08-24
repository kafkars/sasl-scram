//! Secret ownership, zeroization, redaction, and diagnostic regression coverage.

#![cfg(feature = "sha256")]

use sasl_scram::{
    Algorithm, AsciiProfile, AwaitingServerFinal, AwaitingServerFirst, ChannelBinding,
    ChannelBindingData, ChannelBindingMode, ChannelBindingName, ClientConfig, ClientConfigBuilder,
    ConcealmentKey, Error, NeedCredential, NeedIdentityPreparation, OutboundMessage,
    PendingDerivation, PendingServerCredential, PreparedAuthenticationIdentity,
    PreparedAuthorizationIdentity, PreparedCredentials, PreparedPassword,
    ReceivedAuthenticationIdentity, ReceivedAuthorizationIdentity, ResourceLimits, Salt,
    SecretBytes, SecretString, Server, ServerConfig, ServerCredential,
    message::{ClientFinalWithoutProof, ServerFirst, encode_server_final_verifier},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn every_owned_sensitive_public_type_guarantees_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<SecretBytes>();
    assert_zeroize_on_drop::<SecretString>();
    assert_zeroize_on_drop::<PreparedAuthenticationIdentity>();
    assert_zeroize_on_drop::<PreparedAuthorizationIdentity>();
    assert_zeroize_on_drop::<ReceivedAuthenticationIdentity>();
    assert_zeroize_on_drop::<ReceivedAuthorizationIdentity>();
    assert_zeroize_on_drop::<PreparedPassword>();
    assert_zeroize_on_drop::<PreparedCredentials>();
    assert_zeroize_on_drop::<ChannelBindingName>();
    assert_zeroize_on_drop::<ChannelBindingData>();
    assert_zeroize_on_drop::<ChannelBinding>();
    assert_zeroize_on_drop::<ChannelBindingMode>();
    assert_zeroize_on_drop::<OutboundMessage>();
    assert_zeroize_on_drop::<ClientFinalWithoutProof>();
    assert_zeroize_on_drop::<ClientConfig>();
    assert_zeroize_on_drop::<ClientConfigBuilder>();
    assert_zeroize_on_drop::<AwaitingServerFirst>();
    assert_zeroize_on_drop::<PendingDerivation>();
    assert_zeroize_on_drop::<AwaitingServerFinal>();
    assert_zeroize_on_drop::<Salt>();
    assert_zeroize_on_drop::<ServerCredential>();
    assert_zeroize_on_drop::<PendingServerCredential>();
    assert_zeroize_on_drop::<ConcealmentKey>();
    assert_zeroize_on_drop::<Server>();
    assert_zeroize_on_drop::<NeedCredential>();
    assert_zeroize_on_drop::<NeedIdentityPreparation>();
}

#[test]
fn prepared_identity_diagnostics_are_redacted() -> Result<(), Error> {
    let authentication =
        PreparedAuthenticationIdentity::from_protocol_profile("private-authentication")?;
    let authorization =
        PreparedAuthorizationIdentity::from_protocol_profile("private-authorization")?;

    assert_redacted(&authentication, &["private-authentication"]);
    assert_redacted(&authorization, &["private-authorization"]);
    Ok(())
}

#[test]
fn explicit_zeroization_clears_all_owned_credential_material() -> Result<(), Error> {
    let mut bytes = SecretBytes::new(b"byte-secret".as_slice());
    assert_redacted(&bytes, &["byte-secret"]);
    bytes.zeroize();
    assert!(bytes.expose_secret().iter().all(|byte| *byte == 0));

    let mut text = SecretString::new("text-secret");
    assert_redacted(&text, &["text-secret"]);
    text.zeroize();
    assert!(text.is_empty());

    let mut credentials = PreparedCredentials::from_protocol_profile(
        PreparedAuthenticationIdentity::from_protocol_profile("private-user")?,
        Some(PreparedAuthorizationIdentity::from_protocol_profile(
            "private-role",
        )?),
        PreparedPassword::from_protocol_profile(SecretBytes::new(b"private-password".as_slice())),
    );
    assert_redacted(
        &credentials,
        &["private-user", "private-role", "private-password"],
    );
    credentials.zeroize();
    assert!(
        credentials
            .authentication_identity()
            .as_str()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        credentials
            .authorization_identity()
            .is_some_and(|identity| identity.as_str().as_bytes().iter().all(|byte| *byte == 0))
    );
    assert!(
        credentials
            .password()
            .expose_secret()
            .iter()
            .all(|byte| *byte == 0)
    );
    Ok(())
}

#[test]
fn binding_and_message_owners_zeroize_without_loggable_contents() -> Result<(), Error> {
    let limits = ResourceLimits::default();
    let binding = ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new(b"binding-secret".as_slice())),
        &limits,
    )?;
    let mut mode = ChannelBindingMode::Required(binding);
    assert_redacted(&mode, &["binding-secret"]);
    mode.zeroize();
    assert!(matches!(
        &mode,
        ChannelBindingMode::Required(binding)
            if binding.name().as_str().as_bytes().iter().all(|byte| *byte == 0)
                && binding.data().expose_secret().iter().all(|byte| *byte == 0)
    ));

    let mut message = encode_server_final_verifier(b"verifier-secret", &limits)?;
    assert_redacted(&message, &["verifier-secret"]);
    message.zeroize();
    assert!(message.as_bytes().iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn configurations_and_errors_do_not_retain_sensitive_input() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare(
        "configuration-user",
        SecretString::new("configuration-password"),
    )?;
    let builder = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported);
    assert_redacted(&builder, &["configuration-user", "configuration-password"]);
    let config = builder.build()?;
    assert_redacted(&config, &["configuration-user", "configuration-password"]);

    let binding = ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new(b"server-binding-secret".as_slice())),
        &ResourceLimits::default(),
    )?;
    let server = Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256).build()?,
        ChannelBindingMode::Required(binding),
    )?;
    assert_redacted(&server, &["server-binding-secret"]);

    let peer_material = "peer-controlled-sensitive-value";
    let message = format!("r=nonce,s=c2FsdA==,i=4096,x={peer_material},r=duplicate");
    let Err(error) = ServerFirst::parse(message.as_bytes(), &ResourceLimits::default()) else {
        return Err(sasl_scram::StateError::UnexpectedMessage.into());
    };
    let error = Error::from(error);
    assert_redacted(&error, &[peer_material, "duplicate"]);
    assert!(!error.to_string().contains(peer_material));
    Ok(())
}

fn assert_redacted(value: &impl core::fmt::Debug, forbidden: &[&str]) {
    let debug = format!("{value:?}");
    for value in forbidden {
        assert!(!debug.contains(value));
    }
}
