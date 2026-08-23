//! Bounded parser and client-state coverage across one arbitrary conversation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sasl_scram::{
    Algorithm, AsciiProfile, ChannelBinding, ChannelBindingData, ChannelBindingMode,
    ChannelBindingName, Client, ClientConfig, ClientPolicy, ConcealmentKey, ConcealmentProfile,
    CredentialResponse, IterationCount, IterationPolicy, NonceError, NonceSource, ProofResult,
    ResourceLimits, SecretBytes, SecretString, Server, ServerConfig, ServerPolicy,
    message::{ClientFinal, ClientFirst, ServerFinal, ServerFirst},
};

struct ZeroNonce;

impl NonceSource for ZeroNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        output.fill(0);
        Ok(())
    }
}

fuzz_target!(|input: &[u8]| {
    let quarter = input.len() / 4;
    let first_end = quarter;
    let second_end = quarter.saturating_mul(2);
    let third_end = quarter.saturating_mul(3);
    let limits = ResourceLimits::default();
    let _client_first = ClientFirst::parse(&input[..first_end], &limits);
    let _server_first = ServerFirst::parse(&input[first_end..second_end], &limits);
    let _client_final = ClientFinal::parse(&input[second_end..third_end], &limits);
    let _server_final = ServerFinal::parse(&input[third_end..], &limits);

    exercise_client(input, limits);
    exercise_server(input, limits);
});

fn exercise_client(input: &[u8], limits: ResourceLimits) {
    let Some((&selector, messages)) = input.split_first() else {
        return;
    };
    let split = usize::from(selector) % messages.len().saturating_add(1);
    let (server_first, server_final) = messages.split_at(split);
    let one = core::num::NonZeroU32::MIN;
    let eight = one.saturating_add(7);
    let Ok(iterations) = IterationPolicy::new(one, eight) else {
        return;
    };
    let policy = ClientPolicy::new(limits, iterations);
    let Ok(credentials) = AsciiProfile::prepare("user", SecretString::new("password")) else {
        return;
    };
    let Some(channel_binding) = fuzz_channel_binding(selector, limits) else {
        return;
    };
    let Ok(config) = ClientConfig::builder(fuzz_algorithm(selector))
        .credentials(credentials)
        .channel_binding(channel_binding)
        .policy(policy)
        .build()
    else {
        return;
    };
    let Ok((client, _)) = Client::start(config, &mut ZeroNonce) else {
        return;
    };
    assert_redacted(&client);
    let Ok(pending) = client.receive_server_first(server_first) else {
        return;
    };
    assert_redacted(&pending);
    let Ok((client, _)) = pending.derive() else {
        return;
    };
    assert_redacted(&client);
    let _authenticated = client.receive_server_final(server_final);
}

fn exercise_server(input: &[u8], limits: ResourceLimits) {
    let Some((&selector, messages)) = input.split_first() else {
        return;
    };
    let split = usize::from(selector) % messages.len().saturating_add(1);
    let (client_first, client_final) = messages.split_at(split);
    let one = core::num::NonZeroU32::MIN;
    let eight = one.saturating_add(7);
    let Ok(iterations) = IterationPolicy::new(one, eight) else {
        return;
    };
    let policy = ServerPolicy::new(limits, iterations);
    let algorithm = fuzz_algorithm(selector);
    let Ok(config) = ServerConfig::builder(algorithm).policy(policy).build() else {
        return;
    };
    let Some(channel_binding) = fuzz_channel_binding(selector, limits) else {
        return;
    };
    let Ok(server) = Server::with_channel_binding(config, channel_binding) else {
        return;
    };
    let Ok(received) = server.receive_client_first(client_first) else {
        return;
    };
    assert_redacted(&received);
    let Ok((authentication_identity, authorization_identity)) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )
    else {
        return;
    };
    let Ok(pending) = received.accept_prepared(authentication_identity, authorization_identity)
    else {
        return;
    };
    let Ok(key) = ConcealmentKey::new(SecretBytes::new([0x33_u8; 32].as_slice())) else {
        return;
    };
    let profile = ConcealmentProfile::new(
        core::num::NonZeroUsize::MIN.saturating_add(15),
        IterationCount::new(one),
    );
    let Ok(response): Result<CredentialResponse<()>, _> = pending.conceal(&key, profile) else {
        return;
    };
    let Ok((server, _)) = pending.resume(response, &mut ZeroNonce) else {
        return;
    };
    assert_redacted(&server);
    let Ok(result) = server.receive_client_final(client_final) else {
        return;
    };
    assert_redacted(&result);
    assert!(matches!(result, ProofResult::Rejected { .. }));
}

fn fuzz_algorithm(selector: u8) -> Algorithm {
    if selector & 0x80 == 0 {
        Algorithm::Sha256
    } else {
        Algorithm::Sha512
    }
}

fn fuzz_channel_binding(selector: u8, limits: ResourceLimits) -> Option<ChannelBindingMode> {
    match selector % 3 {
        0 => Some(ChannelBindingMode::Unsupported),
        1 => Some(ChannelBindingMode::AvailableButNotNegotiated),
        _ => ChannelBinding::new(
            ChannelBindingName::new("tls-exporter").ok()?,
            ChannelBindingData::new(SecretBytes::new(b"fuzz binding data".as_slice())),
            &limits,
        )
        .ok()
        .map(ChannelBindingMode::Required),
    }
}

fn assert_redacted(value: &impl core::fmt::Debug) {
    let debug = format!("{value:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("password"));
}
