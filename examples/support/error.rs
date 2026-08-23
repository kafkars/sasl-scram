//! Bounded errors for failures detected by the reference applications.

use core::fmt;

use sasl_scram::{Algorithm, Error, PolicyError, PreparationError};

#[derive(Debug)]
pub(crate) enum ReferenceError {
    Scram(Error),
    App(&'static str),
}

impl ReferenceError {
    pub(crate) const fn app(message: &'static str) -> Self {
        Self::App(message)
    }
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scram(error) => fmt::Display::fmt(error, formatter),
            Self::App(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ReferenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scram(error) => Some(error),
            Self::App(_) => None,
        }
    }
}

impl From<Error> for ReferenceError {
    fn from(error: Error) -> Self {
        Self::Scram(error)
    }
}

impl From<PolicyError> for ReferenceError {
    fn from(error: PolicyError) -> Self {
        Self::Scram(error.into())
    }
}

impl From<PreparationError> for ReferenceError {
    fn from(error: PreparationError) -> Self {
        Self::Scram(error.into())
    }
}

pub(crate) fn require_algorithm(
    actual: Algorithm,
    expected: Algorithm,
) -> Result<(), ReferenceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ReferenceError::app("unexpected SCRAM algorithm"))
    }
}
