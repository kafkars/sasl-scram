//! Deterministic unknown-user credentials and lookup response ownership.

use core::{fmt, num::NonZeroUsize};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Algorithm, Error, IterationCount, PolicyError, PreparedAuthenticationIdentity, Salt,
    SaltPolicy, SecretBytes, ServerCredential,
};

const MINIMUM_CONCEALMENT_KEY_BYTES: usize = 32;

/// Public verifier shape reproduced for deterministic unknown-user records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcealmentProfile {
    salt_bytes: NonZeroUsize,
    iterations: IterationCount,
}

impl ConcealmentProfile {
    /// Creates a public credential shape from salt length and iteration count.
    pub const fn new(salt_bytes: NonZeroUsize, iterations: IterationCount) -> Self {
        Self {
            salt_bytes,
            iterations,
        }
    }

    /// Returns the decoded synthetic salt length.
    pub const fn salt_bytes(self) -> NonZeroUsize {
        self.salt_bytes
    }

    /// Returns the synthetic credential iteration count.
    pub const fn iterations(self) -> IterationCount {
        self.iterations
    }
}

/// Server-side secret used to derive deterministic unknown-user verifier records.
pub struct ConcealmentKey(SecretBytes);

impl ConcealmentKey {
    /// Validates and owns at least 32 bytes of caller-generated key material.
    pub fn new(key: SecretBytes) -> Result<Self, PolicyError> {
        if key.len() < MINIMUM_CONCEALMENT_KEY_BYTES {
            return Err(PolicyError::ConcealmentKeyTooShort {
                length: key.len(),
                minimum: MINIMUM_CONCEALMENT_KEY_BYTES,
            });
        }
        Ok(Self(key))
    }

    pub(super) fn derive_credential(
        &self,
        algorithm: Algorithm,
        identity: &PreparedAuthenticationIdentity,
        profile: ConcealmentProfile,
    ) -> Result<ServerCredential, Error> {
        if algorithm.output_len().is_none() {
            return Err(PolicyError::AlgorithmNotPermitted.into());
        }
        let derived = crate::crypto::derive_synthetic_credential(
            algorithm,
            self.0.expose_secret(),
            identity.as_str().as_bytes(),
            profile.salt_bytes.get(),
        )?;
        let (salt, stored_key, server_key) = derived.into_parts();
        let exact_salt_policy = SaltPolicy::new(profile.salt_bytes, profile.salt_bytes)?;
        ServerCredential::from_verifier_parts(
            algorithm,
            Salt::with_policy(salt, exact_salt_policy)?,
            profile.iterations,
            stored_key,
            server_key,
        )
        .map_err(Into::into)
    }
}

impl Zeroize for ConcealmentKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ConcealmentKey {}

impl fmt::Debug for ConcealmentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConcealmentKey")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Caller-supplied lookup result that never exposes an unknown-user variant.
#[non_exhaustive]
pub enum CredentialResponse<P> {
    /// A known identity with its application authentication principal.
    Known {
        /// Caller-owned authentication principal.
        principal: P,
        /// Stored SCRAM verifier record.
        credential: ServerCredential,
    },
    /// An unknown identity represented by deterministic synthetic material.
    Concealed {
        /// Synthetic verifier that must never produce an application principal.
        synthetic: ServerCredential,
    },
}

impl<P> fmt::Debug for CredentialResponse<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialResponse")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
