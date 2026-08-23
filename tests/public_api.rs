//! Compile-and-behavior checks for the deliberate scaffold facade.

use core::num::NonZeroU32;

use sasl_scram::{
    Algorithm, AsciiProfile, ChannelBinding, ChannelBindingData, ChannelBindingMode,
    ChannelBindingName, ClientPolicy, IterationCount, IterationPolicy, ResourceLimits, SecretBytes,
    SecretString, ServerPolicy,
};

#[test]
fn documented_ascii_preparation_path_compiles() -> Result<(), sasl_scram::PreparationError> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;

    assert_eq!(credentials.authentication_identity().as_str(), "user");
    assert!(credentials.authorization_identity().is_none());
    assert_eq!(credentials.password().len(), 6);
    assert!(!format!("{credentials:?}").contains("pencil"));
    Ok(())
}

#[cfg(feature = "saslprep")]
#[test]
fn documented_rfc5802_preparation_path_compiles() -> Result<(), sasl_scram::PreparationError> {
    use sasl_scram::Rfc5802Profile;

    let credentials = Rfc5802Profile::prepare("user", SecretString::new("pencil"))?;
    let password = Rfc5802Profile::prepare_password(SecretString::new("pencil"))?;

    assert_eq!(credentials.authentication_identity().as_str(), "user");
    assert_eq!(credentials.password().expose_secret(), b"pencil");
    assert_eq!(password.expose_secret(), b"pencil");
    Ok(())
}

#[test]
fn explicit_policy_and_channel_binding_types_compose() -> Result<(), sasl_scram::PolicyError> {
    let limits = ResourceLimits::builder()
        .max_message_bytes(4096)
        .max_channel_binding_bytes(64)
        .build()?;
    let iterations = IterationPolicy::new(
        NonZeroU32::MIN.saturating_add(4095),
        NonZeroU32::MIN.saturating_add(199_999),
    )?;
    iterations.validate(IterationCount::new(NonZeroU32::MIN.saturating_add(32_767)))?;
    let binding = ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new([7_u8; 32].as_slice())),
        &limits,
    )?;
    let mode = ChannelBindingMode::Required(binding);
    let policy = ClientPolicy::new(limits, iterations);
    let server_policy = ServerPolicy::new(limits, iterations);

    assert!(matches!(mode, ChannelBindingMode::Required(_)));
    assert_eq!(policy.resources().max_message_bytes(), 4096);
    assert_eq!(server_policy.resources().max_message_bytes(), 4096);
    assert_eq!(Algorithm::Sha256.mechanism_name(), "SCRAM-SHA-256");
    assert_eq!(
        Algorithm::Sha256.plus_mechanism_name(),
        "SCRAM-SHA-256-PLUS"
    );
    Ok(())
}

#[test]
fn digit_leading_channel_binding_names_follow_gs2_abnf() -> Result<(), sasl_scram::PolicyError> {
    let name = ChannelBindingName::new("1-example")?;

    assert_eq!(name.as_str(), "1-example");
    Ok(())
}

#[test]
fn empty_present_authorization_identity_is_rejected() {
    let result = sasl_scram::PreparedAuthorizationIdentity::from_protocol_profile("");

    assert_eq!(
        result.err(),
        Some(sasl_scram::PreparationError::InvalidAuthorizationIdentity)
    );
}

#[cfg(feature = "saslprep")]
#[test]
fn rfc5802_distinguishes_query_and_stored_string_preparation() {
    use sasl_scram::{PreparationError, Rfc5802Profile};

    let unassigned_in_unicode_3_2 = '\u{0487}';
    let identity = format!("user{unassigned_in_unicode_3_2}");
    let accepted = Rfc5802Profile::prepare(&identity, SecretString::new("password"));
    let rejected = Rfc5802Profile::prepare(
        "user",
        SecretString::new(format!("password{unassigned_in_unicode_3_2}")),
    );

    assert_eq!(
        accepted
            .as_ref()
            .map(|credentials| credentials.authentication_identity().as_str()),
        Ok(identity.as_str())
    );
    assert_eq!(rejected.err(), Some(PreparationError::InvalidPassword));
}

#[cfg(feature = "saslprep")]
#[test]
fn query_preparation_uses_unicode_3_2_assignment_boundaries()
-> Result<(), sasl_scram::PreparationError> {
    use sasl_scram::Rfc5802Profile;

    let assigned_after_unicode_3_2 = '\u{03f9}';
    let identity = assigned_after_unicode_3_2.to_string();
    let credentials = Rfc5802Profile::prepare(&identity, SecretString::new("password"))?;
    let rejected = Rfc5802Profile::prepare(
        "user",
        SecretString::new(assigned_after_unicode_3_2.to_string()),
    );

    assert_eq!(credentials.authentication_identity().as_str(), identity);
    assert_eq!(
        rejected.err(),
        Some(sasl_scram::PreparationError::InvalidPassword)
    );
    Ok(())
}
