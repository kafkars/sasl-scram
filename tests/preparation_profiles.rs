//! RFC 4013 vectors and strict-ASCII credential preparation coverage.

use sasl_scram::{AsciiProfile, PreparationError, SecretString};

#[cfg(feature = "saslprep")]
#[test]
fn rfc4013_mapping_normalization_and_bidi_rules_apply() -> Result<(), sasl_scram::PreparationError>
{
    use sasl_scram::Rfc5802Profile;

    let mapped =
        Rfc5802Profile::prepare("I\u{00ad}\u{2168}", SecretString::new("\u{00aa}\u{00a0}x"))?;
    let prohibited = Rfc5802Profile::prepare("a\u{0007}b", SecretString::new("password"));
    let bad_bidi = Rfc5802Profile::prepare("\u{0627}1", SecretString::new("password"));

    assert_eq!(mapped.authentication_identity().as_str(), "IIX");
    assert_eq!(mapped.password().expose_secret(), "a x".as_bytes());
    assert_eq!(
        prohibited.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    assert_eq!(
        bad_bidi.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    Ok(())
}

#[cfg(feature = "saslprep")]
#[test]
fn passwords_reject_unicode_3_2_unassigned_code_points_before_normalization() {
    use sasl_scram::Rfc5802Profile;

    let assigned_later_with_compatibility_mapping = '\u{03f9}';
    let result = Rfc5802Profile::prepare(
        "user",
        SecretString::new(assigned_later_with_compatibility_mapping.to_string()),
    );

    assert_eq!(result.err(), Some(PreparationError::InvalidPassword));
}

#[cfg(feature = "saslprep")]
#[test]
fn bidirectional_checks_use_unicode_3_2_properties() {
    use sasl_scram::Rfc5802Profile;

    let arabic_with_braille = "\u{0627}\u{2800}\u{0628}";
    let arabic_with_old_l_character = "\u{0627}\u{17b4}\u{0628}";
    let accepted = Rfc5802Profile::prepare(arabic_with_braille, SecretString::new("password"));
    let rejected =
        Rfc5802Profile::prepare(arabic_with_old_l_character, SecretString::new("password"));
    let accepted_password = Rfc5802Profile::prepare("user", SecretString::new(arabic_with_braille));
    let rejected_password =
        Rfc5802Profile::prepare("user", SecretString::new(arabic_with_old_l_character));

    assert_eq!(
        accepted
            .as_ref()
            .map(|credentials| credentials.authentication_identity().as_str()),
        Ok(arabic_with_braille)
    );
    assert_eq!(
        rejected.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    assert_eq!(
        accepted_password
            .as_ref()
            .map(|credentials| credentials.password().expose_secret()),
        Ok(arabic_with_braille.as_bytes())
    );
    assert_eq!(
        rejected_password.err(),
        Some(PreparationError::InvalidPassword)
    );
}

#[test]
fn ascii_profile_is_printable_and_nonempty_for_identities() {
    let control_identity = AsciiProfile::prepare("user\n", SecretString::new("password"));
    let unicode_identity = AsciiProfile::prepare("usér", SecretString::new("password"));
    let empty_identity = AsciiProfile::prepare("", SecretString::new("password"));
    let control_password = AsciiProfile::prepare("user", SecretString::new("pass\nword"));

    assert_eq!(
        control_identity.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    assert_eq!(
        unicode_identity.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    assert_eq!(
        empty_identity.err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    assert_eq!(
        control_password.err(),
        Some(PreparationError::InvalidPassword)
    );
}
