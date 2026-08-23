//! Server verifier records, explicit derivation, and synthetic concealment.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Algorithm, Error, IterationCount, PolicyError, PreparedPassword, Salt, SecretBytes,
    ServerPolicy,
};

/// Binary SCRAM verifier material independent of any storage serialization.
pub struct ServerCredential {
    pub(super) algorithm: Algorithm,
    pub(super) salt: Salt,
    pub(super) iterations: IterationCount,
    pub(super) stored_key: SecretBytes,
    pub(super) server_key: SecretBytes,
}

impl ServerCredential {
    /// Validates and owns verifier parts decoded by a protocol-specific storage codec.
    pub fn from_verifier_parts(
        algorithm: Algorithm,
        salt: Salt,
        iterations: IterationCount,
        stored_key: SecretBytes,
        server_key: SecretBytes,
    ) -> Result<Self, PolicyError> {
        validate_algorithm_and_keys(algorithm, &stored_key, &server_key)?;
        Ok(Self {
            algorithm,
            salt,
            iterations,
            stored_key,
            server_key,
        })
    }

    /// Creates an explicit PBKDF2 task for verifier generation from a prepared password.
    pub fn prepare(
        algorithm: Algorithm,
        password: PreparedPassword,
        salt: Salt,
        iterations: IterationCount,
    ) -> Result<PendingServerCredential, PolicyError> {
        if algorithm.output_len().is_none() {
            return Err(PolicyError::AlgorithmNotPermitted);
        }
        Ok(PendingServerCredential {
            algorithm,
            password,
            salt,
            iterations,
        })
    }

    /// Returns the complete algorithm profile.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the owned salt.
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Returns the iteration count.
    pub const fn iterations(&self) -> IterationCount {
        self.iterations
    }

    /// Explicitly returns the stored key for storage codecs.
    pub const fn stored_key(&self) -> &SecretBytes {
        &self.stored_key
    }

    /// Explicitly returns the server key for storage codecs.
    pub const fn server_key(&self) -> &SecretBytes {
        &self.server_key
    }

    pub(super) fn validate(&self, policy: ServerPolicy) -> Result<(), Error> {
        validate_algorithm_and_keys(self.algorithm, &self.stored_key, &self.server_key)?;
        policy.iterations().validate(self.iterations)?;
        if self.salt.len() > policy.resources().max_salt_bytes() {
            return Err(crate::ProtocolError::SaltTooLarge {
                length: self.salt.len(),
                maximum: policy.resources().max_salt_bytes(),
            }
            .into());
        }
        policy.salt().validate(self.salt.len())?;
        Ok(())
    }
}

impl Zeroize for ServerCredential {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.stored_key.zeroize();
        self.server_key.zeroize();
    }
}

impl ZeroizeOnDrop for ServerCredential {}

impl fmt::Debug for ServerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerCredential")
            .field("algorithm", &self.algorithm)
            .field("contents", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// One prepared password awaiting explicit verifier PBKDF2 derivation.
///
/// ```compile_fail
/// fn derive_twice(state: sasl_scram::PendingServerCredential) {
///     let _first = state.derive();
///     let _second = state.derive();
/// }
/// ```
///
/// ```compile_fail
/// fn clone_pending(state: &sasl_scram::PendingServerCredential) {
///     let _copy = Clone::clone(state);
/// }
/// ```
pub struct PendingServerCredential {
    algorithm: Algorithm,
    password: PreparedPassword,
    salt: Salt,
    iterations: IterationCount,
}

impl PendingServerCredential {
    /// Performs PBKDF2 and returns a password-free server verifier record.
    pub fn derive(self) -> Result<ServerCredential, Error> {
        let Self {
            algorithm,
            password,
            salt,
            iterations,
        } = self;
        let derived = crate::crypto::derive_server_credential(
            algorithm,
            password.expose_secret(),
            salt.expose_bytes(),
            iterations.get(),
        )?;
        drop(password);
        let (stored_key, server_key) = derived.into_parts();
        ServerCredential::from_verifier_parts(algorithm, salt, iterations, stored_key, server_key)
            .map_err(Into::into)
    }
}

impl ZeroizeOnDrop for PendingServerCredential {}

impl fmt::Debug for PendingServerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingServerCredential")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

fn validate_algorithm_and_keys(
    algorithm: Algorithm,
    stored_key: &SecretBytes,
    server_key: &SecretBytes,
) -> Result<(), PolicyError> {
    let Some(output_len) = algorithm.output_len() else {
        return Err(PolicyError::AlgorithmNotPermitted);
    };
    if stored_key.len() != output_len || server_key.len() != output_len {
        return Err(PolicyError::InvalidCredential);
    }
    Ok(())
}
