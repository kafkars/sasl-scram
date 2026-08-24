//! Client configuration policy boundaries.

#![cfg(feature = "sha256")]

use sasl_scram::{
    Algorithm, AsciiProfile, ChannelBindingMode, ClientConfig, Error, PolicyError, SecretString,
};

#[test]
fn client_configuration_requires_explicit_binding_and_credentials() -> Result<(), Error> {
    assert!(matches!(
        ClientConfig::builder(Algorithm::Sha256).build(),
        Err(PolicyError::MissingChannelBindingMode)
    ));
    assert!(matches!(
        ClientConfig::builder(Algorithm::Sha256)
            .channel_binding(ChannelBindingMode::Unsupported)
            .build(),
        Err(PolicyError::MissingCredentials)
    ));

    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    assert!(matches!(
        ClientConfig::builder(Algorithm::Sha256)
            .credentials(credentials)
            .build(),
        Err(PolicyError::MissingChannelBindingMode)
    ));
    Ok(())
}
