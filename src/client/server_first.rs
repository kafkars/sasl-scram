//! Stateful server-first validation before derivation.

use crate::{
    AuthenticationProperties, PolicyError, ProtocolError, SecretBytes,
    client::{AwaitingServerFirst, PendingDerivation},
    message::{
        AuthenticationTranscript, ServerFirst, decode_base64, encode_client_final_without_proof,
    },
};

impl AwaitingServerFirst {
    /// Consumes a server-first message and returns an explicit derivation task.
    ///
    /// ```compile_fail
    /// fn receive_twice(state: sasl_scram::AwaitingServerFirst, message: &[u8]) {
    ///     let _first = state.receive_server_first(message);
    ///     let _second = state.receive_server_first(message);
    /// }
    /// ```
    pub fn receive_server_first(self, input: &[u8]) -> Result<PendingDerivation, crate::Error> {
        let limits = self.policy.resources();
        let server_first = ServerFirst::parse(input, &limits)?;
        validate_combined_nonce(self.client_nonce.expose_secret(), server_first.nonce())?;
        self.policy
            .iterations()
            .validate(server_first.iterations())?;
        let salt = SecretBytes::new(decode_base64(server_first.salt_base64())?.into_boxed_slice());
        self.policy.salt().validate(salt.len())?;
        let client_final = encode_client_final_without_proof(
            &self.channel_binding,
            self.credentials.authorization_identity(),
            server_first.nonce(),
            &limits,
        )?;
        let output_len = self
            .algorithm
            .output_len()
            .ok_or(PolicyError::AlgorithmNotPermitted)?;
        client_final.validate_proof_length(output_len, &limits)?;
        let auth_message = AuthenticationTranscript::from_fragments(
            self.client_first_bare.expose_secret(),
            server_first.raw(),
            client_final.as_bytes(),
        )
        .to_owned_message(&limits)?;
        let properties = AuthenticationProperties::from_mode(self.algorithm, &self.channel_binding);
        Ok(PendingDerivation {
            algorithm: self.algorithm,
            password: self.credentials.into_password(),
            salt,
            iterations: server_first.iterations(),
            auth_message,
            client_final,
            properties,
            policy: self.policy,
        })
    }
}

fn validate_combined_nonce(client: &[u8], combined: &[u8]) -> Result<(), ProtocolError> {
    if combined.len() <= client.len() || !combined.starts_with(client) {
        return Err(ProtocolError::InvalidNonce);
    }
    Ok(())
}
