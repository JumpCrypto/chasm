//! Error types

use abscissa_core::error::{BoxError, Context};
use std::{
    fmt::{self, Display},
    io,
    ops::Deref,
};
use thiserror::Error;

use crate::crypto;

pub type Result<T> = core::result::Result<T, Error>;

/// Kinds of errors
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Error in configuration file
    #[error("config error")]
    Config,

    /// Crypto error
    #[error("Crypto error")]
    Crypto(crypto::Error),

    /// Input/output error
    #[error("I/O error")]
    Io,

    /// Errors originating in the Tendermint RPC crate
    #[error("Tendermint RPC error")]
    TendermintRpcError,

    /// Errors originating in the Tonic crate
    #[error("Tonic error")]
    TonicError,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

/// Error type
#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Deref for Error {
    type Target = Context<ErrorKind>;

    fn deref(&self) -> &Context<ErrorKind> {
        &self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Context::new(kind, None).into()
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(context: Context<ErrorKind>) -> Self {
        Error(Box::new(context))
    }
}

impl From<crypto::Error> for Error {
    fn from(err: crypto::Error) -> Self {
        ErrorKind::Crypto(err).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        ErrorKind::Io.context(err).into()
    }
}

#[cfg(feature="standalone")]
impl From<tendermint_rpc::Error> for Error {
    fn from(other: tendermint_rpc::Error) -> Self {
        ErrorKind::TendermintRpcError.context(other).into()
    }
}

#[cfg(feature="standalone")]
impl From<tonic::transport::Error> for Error {
    fn from(other: tonic::transport::Error) -> Self {
        ErrorKind::TonicError.context(other).into()
    }
}
