//! SHA-512-PLUS loopback proving explicit binding and derivation offload.

mod support;

use core::num::NonZeroU32;

use sasl_scram::{
    Algorithm, AsciiProfile, AuthorizationOutcome, ChannelBinding, ChannelBindingData,
    ChannelBindingMode, ChannelBindingName, Client, ClientConfig, CredentialResponse,
    IterationCount, ProofResult, ResourceLimits, Salt, SecretBytes, SecretString, Server,
    ServerConfig, ServerCredential,
};

use support::{FixedNonce, ReferenceError, require_algorithm};

fn main() -> Result<(), ReferenceError> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha512)
        .credentials(credentials)
        .channel_binding(binding_mode()?)
        .build()?;
    let server_config = ServerConfig::builder(Algorithm::Sha512).build()?;
    let server = Server::with_channel_binding(server_config, binding_mode()?)?;
    let credential = server_credential()?;

    let (client, client_first) = Client::start(client_config, &mut FixedNonce::new([3_u8; 15]))?;
    let received = server.receive_client_first(client_first.as_bytes())?;
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    let need = received.accept_prepared(authentication_identity, authorization_identity)?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: 42_u64,
            credential,
        },
        &mut FixedNonce::new([4_u8; 15]),
    )?;

    let pending = client.receive_server_first(server_first.as_bytes())?;
    let worker = std::thread::spawn(move || pending.derive());
    let (client, client_final) = worker
        .join()
        .map_err(|_| ReferenceError::app("derivation worker terminated unexpectedly"))??;

    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(ReferenceError::app("unexpected proof outcome"));
    };
    let AuthorizationOutcome::Authorized {
        authenticated,
        server_final,
    } = authorization.authorize(84_u64)?
    else {
        return Err(ReferenceError::app("unexpected authenticated principal"));
    };

    require_algorithm(authenticated.algorithm(), Algorithm::Sha512)?;
    if *authenticated.authenticated_principal() != 42 || *authenticated.authorized_principal() != 84
    {
        return Err(ReferenceError::app("unexpected authenticated identity"));
    }
    let client_authenticated = client.receive_server_final(server_final.as_bytes())?;
    require_algorithm(client_authenticated.algorithm(), Algorithm::Sha512)
}

fn binding_mode() -> Result<ChannelBindingMode, ReferenceError> {
    let binding = ChannelBinding::new(
        ChannelBindingName::new("tls-exporter")?,
        ChannelBindingData::new(SecretBytes::new(
            b"reference TLS exporter fixture".as_slice(),
        )),
        &ResourceLimits::default(),
    )?;
    Ok(ChannelBindingMode::Required(binding))
}

fn server_credential() -> Result<ServerCredential, ReferenceError> {
    let password = AsciiProfile::prepare_password(SecretString::new("pencil"))?;
    let pending = ServerCredential::prepare(
        Algorithm::Sha512,
        password,
        Salt::new(SecretBytes::new(b"reference SHA-512 salt".as_slice()))?,
        iterations(),
    )?;
    Ok(pending.derive()?)
}

fn iterations() -> IterationCount {
    IterationCount::new(NonZeroU32::new(4096).unwrap_or(NonZeroU32::MIN))
}
