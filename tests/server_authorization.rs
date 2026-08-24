//! Server identity separation and unbound GS2 negotiation behavior.

#![cfg(feature = "sha256")]

use core::num::NonZeroU32;

use sasl_scram::{
    Algorithm, AsciiProfile, AuthorizationOutcome, ChannelBinding, ChannelBindingData,
    ChannelBindingMode, ChannelBindingName, Client, ClientConfig, ClientPolicy, CredentialResponse,
    Error, IterationCount, IterationPolicy, NonceError, NonceSource, PolicyError, PreparationError,
    PreparedAuthenticationIdentity, PreparedAuthorizationIdentity, PreparedCredentials,
    PreparedPassword, ProofResult, ResourceLimits, Salt, SecretBytes, Server, ServerConfig,
    ServerCredential, ServerPolicy, message::encode_client_first,
};

#[cfg(feature = "saslprep")]
use sasl_scram::Rfc5802Profile;

struct FilledNonce(u8);

impl NonceSource for FilledNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(self.0);
        Ok(())
    }
}

#[test]
fn authentication_authorization_and_application_principal_remain_distinct() -> Result<(), Error> {
    let (client_policy, server_policy) = policies()?;
    let credentials = PreparedCredentials::from_protocol_profile(
        PreparedAuthenticationIdentity::from_protocol_profile("alice")?,
        Some(PreparedAuthorizationIdentity::from_protocol_profile(
            "service-role",
        )?),
        PreparedPassword::from_protocol_profile(SecretBytes::new(b"password".as_slice())),
    );
    let client_config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .policy(client_policy)
        .build()?;
    let (client, client_first) = Client::start(client_config, &mut FilledNonce(0))?;
    let received = Server::new(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(server_policy)
            .build()?,
    )
    .receive_client_first(client_first.as_bytes())?;
    assert_eq!(received.authentication_identity().as_str(), "alice");
    assert_eq!(
        received
            .authorization_identity()
            .map(sasl_scram::ReceivedAuthorizationIdentity::as_str),
        Some("service-role")
    );
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    let need = received.accept_prepared(authentication_identity, authorization_identity)?;
    let lookup = need.credential_request();
    assert_eq!(lookup.authentication_identity().as_str(), "alice");
    assert_eq!(
        lookup
            .authorization_identity()
            .map(PreparedAuthorizationIdentity::as_str),
        Some("service-role")
    );
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: 9001_u64,
            credential: credential()?,
        },
        &mut FilledNonce(1),
    )?;
    let (client, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let ProofResult::Verified(pending) = server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(sasl_scram::AuthenticationError::InvalidProof.into());
    };
    let request = pending.request();
    assert_eq!(request.authentication_identity().as_str(), "alice");
    assert_eq!(
        request
            .authorization_identity()
            .map(PreparedAuthorizationIdentity::as_str),
        Some("service-role")
    );
    assert_eq!(*request.authenticated_principal(), 9001);
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = pending.authorize("service-account-X")?
    else {
        return Err(sasl_scram::AuthenticationError::AuthorizationDenied.into());
    };
    assert_eq!(*authenticated.authenticated_principal(), 9001);
    assert_eq!(*authenticated.authorized_principal(), "service-account-X");
    client.receive_server_final(server_final.as_bytes())?;
    Ok(())
}

#[cfg(feature = "saslprep")]
#[test]
fn received_identities_require_explicit_profile_preparation() -> Result<(), Error> {
    let received = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?)
        .receive_client_first("n,,n=I\u{00ad}X,r=nonce".as_bytes())?;
    assert_eq!(received.authentication_identity().as_str(), "I\u{00ad}X");
    assert_eq!(
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )
        .err(),
        Some(PreparationError::InvalidAuthenticationIdentity)
    );
    let authentication_identity =
        Rfc5802Profile::prepare_authentication_identity(received.authentication_identity())?;
    let need = received.accept_prepared(authentication_identity, None)?;
    assert_eq!(
        need.credential_request().authentication_identity().as_str(),
        "IX"
    );
    Ok(())
}

#[test]
fn prepared_authorization_presence_must_match_the_client_first_message() -> Result<(), Error> {
    let without = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?)
        .receive_client_first(b"n,,n=user,r=nonce")?;
    let authentication =
        AsciiProfile::prepare_authentication_identity(without.authentication_identity())?;
    let injected = Some(PreparedAuthorizationIdentity::from_protocol_profile(
        "role",
    )?);
    assert!(matches!(
        without.accept_prepared(authentication, injected),
        Err(Error::Preparation(
            PreparationError::AuthorizationIdentityMismatch
        ))
    ));

    let with = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?)
        .receive_client_first(b"n,a=role,n=user,r=nonce")?;
    let authentication =
        AsciiProfile::prepare_authentication_identity(with.authentication_identity())?;
    assert!(matches!(
        with.accept_prepared(authentication, None),
        Err(Error::Preparation(
            PreparationError::AuthorizationIdentityMismatch
        ))
    ));
    Ok(())
}

#[cfg(feature = "saslprep")]
#[test]
fn rfc_authentication_and_application_authorization_profiles_compose() -> Result<(), Error> {
    let received = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?)
        .receive_client_first("n,a=service-role,n=I\u{00ad}X,r=nonce".as_bytes())?;
    let authentication =
        Rfc5802Profile::prepare_authentication_identity(received.authentication_identity())?;
    let authorization = received
        .authorization_identity()
        .map(AsciiProfile::prepare_authorization_identity)
        .transpose()?;
    let need = received.accept_prepared(authentication, authorization)?;
    assert_eq!(
        need.credential_request().authentication_identity().as_str(),
        "IX"
    );
    assert_eq!(
        need.credential_request()
            .authorization_identity()
            .map(PreparedAuthorizationIdentity::as_str),
        Some("service-role")
    );
    Ok(())
}

#[test]
fn unbound_server_accepts_y_but_rejects_plus_before_lookup() -> Result<(), Error> {
    let (client_policy, server_policy) = policies()?;
    let credentials =
        sasl_scram::AsciiProfile::prepare("user", sasl_scram::SecretString::new("password"))?;
    let client = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::AvailableButNotNegotiated)
        .policy(client_policy)
        .build()?;
    let (_, y_first) = Client::start(client, &mut FilledNonce(0))?;
    Server::new(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(server_policy)
            .build()?,
    )
    .receive_client_first(y_first.as_bytes())?;

    let limits = ResourceLimits::default();
    let binding = ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new([1_u8; 32].as_slice())),
        &limits,
    )?;
    let plus_first = encode_client_first(
        &ChannelBindingMode::Required(binding),
        &PreparedAuthenticationIdentity::from_protocol_profile("user")?,
        None,
        b"nonce",
        &limits,
    )?;
    assert!(matches!(
        Server::new(
            ServerConfig::builder(Algorithm::Sha256)
                .policy(server_policy)
                .build()?
        )
        .receive_client_first(plus_first.as_bytes()),
        Err(Error::Policy(PolicyError::ChannelBindingNotPermitted))
    ));
    Ok(())
}

fn credential() -> Result<ServerCredential, Error> {
    ServerCredential::prepare(
        Algorithm::Sha256,
        PreparedPassword::from_protocol_profile(SecretBytes::new(b"password".as_slice())),
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        iteration(),
    )?
    .derive()
}

fn policies() -> Result<(ClientPolicy, ServerPolicy), Error> {
    let count = NonZeroU32::MIN;
    let iterations = IterationPolicy::new(count, count)?;
    let resources = ResourceLimits::default();
    Ok((
        ClientPolicy::new(resources, iterations),
        ServerPolicy::new(resources, iterations),
    ))
}

fn iteration() -> IterationCount {
    IterationCount::new(NonZeroU32::MIN)
}
