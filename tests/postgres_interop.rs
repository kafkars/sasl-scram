//! Fixed PostgreSQL-style SCRAM-SHA-256-PLUS transcript interoperability fixture.

#![cfg(feature = "sha256")]

use core::num::NonZeroU32;

use sasl_scram::{
    Algorithm, AsciiProfile, AuthenticationError, AuthorizationOutcome, ChannelBinding,
    ChannelBindingData, ChannelBindingMode, ChannelBindingName, Client, ClientConfig, ClientPolicy,
    CredentialResponse, Error, IterationCount, IterationPolicy, NonceError, NonceSource,
    ProofResult, ResourceLimits, Salt, SecretBytes, SecretString, Server, ServerConfig,
    ServerCredential, ServerPolicy,
};

struct SequenceNonce(u8);

impl NonceSource for SequenceNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.saturating_add(1);
        }
        Ok(())
    }
}

#[test]
fn postgres_tls_server_end_point_matches_independent_fixed_vector() -> Result<(), Error> {
    let binding = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let limits = ResourceLimits::default();
    let count = NonZeroU32::MIN.saturating_add(4095);
    let iterations = IterationPolicy::new(count, count)?;
    let client_policy = ClientPolicy::new(limits, iterations);
    let server_policy = ServerPolicy::new(limits, iterations);
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let client_config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(required(&binding, limits)?)
        .policy(client_policy)
        .build()?;
    let (client, client_first) = Client::start(client_config, &mut SequenceNonce(0))?;
    assert_eq!(
        client_first.as_bytes(),
        b"p=tls-server-end-point,,n=user,r=AAECAwQFBgcICQoLDA0O"
    );

    let server = Server::with_channel_binding(
        ServerConfig::builder(Algorithm::Sha256)
            .policy(server_policy)
            .build()?,
        required(&binding, limits)?,
    )?;
    let received = server.receive_client_first(client_first.as_bytes())?;
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    let need = received.accept_prepared(authentication_identity, authorization_identity)?;
    let (server, server_first) = need.resume(
        CredentialResponse::Known {
            principal: "postgres-user",
            credential: credential(count)?,
        },
        &mut SequenceNonce(15),
    )?;
    let expected_server_first = [
        &b"r=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd,"[..],
        &b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"[..],
    ]
    .concat();
    assert_eq!(server_first.as_bytes(), expected_server_first);

    let (client, client_final) = client
        .receive_server_first(server_first.as_bytes())?
        .derive()?;
    let expected_client_final = [
        &b"c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAECAwQFBgcICQoLDA0O"[..],
        &b"DxAREhMUFRYXGBkaGxwdHh8=,"[..],
        &b"r=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd,"[..],
        &b"p=VhCo/1fLuEEUeYkgMH41cQPcbmID+uFtO8znoaPp7GA="[..],
    ]
    .concat();
    assert_eq!(client_final.as_bytes(), expected_client_final);
    let ProofResult::Verified(authorization) =
        server.receive_client_final(client_final.as_bytes())?
    else {
        return Err(AuthenticationError::InvalidProof.into());
    };
    assert_eq!(
        *authorization.request().authenticated_principal(),
        "postgres-user"
    );
    let AuthorizationOutcome::Authorized { server_final, .. } =
        authorization.authorize("postgres-user")?
    else {
        return Err(AuthenticationError::AuthorizationDenied.into());
    };
    assert_eq!(
        server_final.as_bytes(),
        b"v=XRNEfVPxKLwhie4NnysG2v2omJ44JnA7fbQ35yPOvd4="
    );
    client.receive_server_final(server_final.as_bytes())?;
    Ok(())
}

fn required(
    data: &[u8],
    limits: ResourceLimits,
) -> Result<ChannelBindingMode, sasl_scram::PolicyError> {
    Ok(ChannelBindingMode::Required(ChannelBinding::new(
        ChannelBindingName::new("tls-server-end-point")?,
        ChannelBindingData::new(SecretBytes::new(data)),
        &limits,
    )?))
}

fn credential(count: NonZeroU32) -> Result<ServerCredential, Error> {
    let salt = [
        0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa,
        0x81,
    ];
    ServerCredential::prepare(
        Algorithm::Sha256,
        AsciiProfile::prepare_password(SecretString::new("pencil"))?,
        Salt::new(SecretBytes::new(salt.as_slice()))?,
        IterationCount::new(count),
    )?
    .derive()
}
