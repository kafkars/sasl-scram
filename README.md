<h1 align="center">sasl-scram</h1>

<p align="center">
  <strong>Strict, sans-I/O SCRAM for Rust.</strong>
</p>

<p align="center">
  Bounded client and server state machines with exact transcripts, explicit
  proof work, channel binding, and zeroizing secret ownership.
</p>

<p align="center">
  <a href="#install">Install</a>
  <span> · </span>
  <a href="#model">Model</a>
  <span> · </span>
  <a href="#client">Client</a>
  <span> · </span>
  <a href="#server">Server</a>
  <span> · </span>
  <a href="#mechanisms">Mechanisms</a>
  <span> · </span>
  <a href="#qualification">Qualification</a>
</p>

<br />

## Status

The current development snapshot implements `SCRAM-SHA-256` and
`SCRAM-SHA-256-PLUS` client and server roles. The `sha512` feature adds
`SCRAM-SHA-512` and `SCRAM-SHA-512-PLUS` extension profiles.

Continuously hosted interoperability and supported-release qualification are
not complete. Do not deploy version `0.0.1` as a supported authentication
dependency.

## Install

```toml
[dependencies]
sasl-scram = "0.0.1"
```

The minimum supported Rust version is 1.88. The crate always requires `alloc`;
`std` is enabled by default and remains optional.

## Model

```text
application  framing, transport, TLS, deadlines, storage, authorization
                                  │ opaque messages
                                  ▼
sasl-scram   parsing, transcripts, state, proofs, policy, secret ownership
```

The crate performs no I/O. Callers retain transport, TLS, credential lookup,
authorization, retries, and scheduling. Consuming state transitions make one
conversation explicit, while bounded parsers retain the exact authenticated
wire fragments instead of reconstructing them.

## Client

PBKDF2 runs only when the caller invokes `derive`, so an async adapter can move
the `Send` derivation state to its own blocking pool:

```rust
let credentials = sasl_scram::AsciiProfile::prepare(
    "user",
    sasl_scram::SecretString::new("pencil"),
)?;
let config = sasl_scram::ClientConfig::builder(sasl_scram::Algorithm::Sha256)
    .credentials(credentials)
    .channel_binding(sasl_scram::ChannelBindingMode::Unsupported)
    .build()?;

let (client, first) = sasl_scram::Client::start(config, &mut nonce_source)?;
transport.send(first.as_bytes())?;
let pending = client.receive_server_first(&server_first)?;
let (client, final_message) = pending.derive()?;
transport.send(final_message.as_bytes())?;
let authenticated = client.receive_server_final(&server_final)?;
```

Authentication succeeds only after constant-time verification of the server
signature over the exact transcript.

## Server

Credential lookup and authorization are caller-owned continuations. Received
identities must be prepared explicitly before lookup, and a verified proof does
not become an authorized principal without a separate caller decision.

```rust
let server = sasl_scram::Server::new(server_config);
let received = server.receive_client_first(&client_first)?;
let identity = sasl_scram::Rfc5802Profile::prepare_authentication_identity(
    received.authentication_identity(),
)?;
let pending = received.accept_prepared(identity, None)?;
let credential = credential_store.lookup(
    pending.credential_request().authentication_identity(),
)?;
let (server, first) = pending.resume(credential, &mut nonce_source)?;
transport.send(first.as_bytes())?;

match server.receive_client_final(&client_final)? {
    sasl_scram::ProofResult::Verified(pending) => {
        let principal = authorizer.authorize(pending.request())?;
        let outcome = pending.authorize(principal)?;
        send_authorization_outcome(outcome)?;
    }
    sasl_scram::ProofResult::Rejected { server_final } => {
        transport.send(server_final.as_bytes())?;
    }
    _ => return Err(sasl_scram::StateError::UnexpectedMessage.into()),
}
```

Unknown identities can use deterministic synthetic credentials with a
deployment-owned concealment key. Concealed and invalid-proof paths emit the
same terminal error, and concealed users can never produce an application
principal.

## Mechanisms

| Mechanism | Feature | Contract |
| --- | --- | --- |
| `SCRAM-SHA-256` | `sha256` | Standard client and server profile; enabled by default |
| `SCRAM-SHA-256-PLUS` | `sha256` | Caller-supplied channel binding; enabled by default |
| `SCRAM-SHA-512` | `sha512` | Explicit opt-in extension profile |
| `SCRAM-SHA-512-PLUS` | `sha512` | Explicit opt-in extension with channel binding |

Configuration always requires an explicit `Algorithm`; features never select a
mechanism implicitly. PLUS accepts binding bytes extracted by the caller from
the live TLS connection. The crate never calls a TLS API.

The optional `saslprep` feature provides RFC 5802 query and stored-string
preparation. ASCII preparation remains available for protocols that define an
ASCII-only identity contract.

## Security

- Inbound authenticated fragments remain byte-exact.
- Outbound messages are canonical, bounded, and redacted.
- Owned passwords, credentials, bindings, proofs, and transcripts zeroize on
  drop.
- Proof derivation is an explicit work boundary with caller-configured limits.
- Proofs, signatures, and channel-binding values use constant-time comparison.
- Malformed structure, unsupported mandatory extensions, downgrade attempts,
  and policy violations fail closed.
- The public API exposes no sockets, async runtime, TLS implementation,
  credential database, secret serialization, or bring-your-own-crypto trait.

## Reference applications

```sh
cargo run --example scram-sha256-client --locked --offline
cargo run --example continuation-server --locked --offline
cargo run --example scram-sha512-plus --no-default-features --features std,sha512 --locked --offline
```

The examples exercise only the public API. They use deterministic secrets and
nonces as test fixtures, perform no socket I/O, and print no credential or
protocol material.

## Qualification

```sh
zcheck
```

The schema-1 zcheck graph is the canonical gate for repository architecture,
formatting, strict Clippy, the default and complete feature matrices,
independent SHA-256 and SHA-512 `no_std + alloc` builds, tests, examples, every
fuzz target, warning-free rustdoc, dependency policy, package contents, and the
zrail lock.

## Scope

`sasl-scram` owns SCRAM protocol mechanics. It does not own application framing,
transport security, credentials, authorization policy, scheduling, retries, or
observability.

## License

Apache-2.0. See [LICENSE](LICENSE).
