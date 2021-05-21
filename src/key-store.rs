use std::result;

use keys::AsymmetricKeyError;
use secret::SymmetricKeyError;
use types::{AsymmetricKeyType, SymmetricKeyType};

pub mod keys;
pub mod secret;
pub mod traits;
pub mod types;

#[cfg(feature = "sqlite-backend")]
pub mod sqlite_key_store;

mod util;

pub struct KeyStoreIdentifier([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    WriteError,
    ReadError,
    UpdateError,
    DeleteError,
    UnsupportedKeyType(AsymmetricKeyType),
    UnsupportedSecretType(SymmetricKeyType),
    SymmetricKeyError(SymmetricKeyError),
    AsymmetricKeyError(AsymmetricKeyError),
    UnsupportedAlgorithm(String),
    InvalidLength(String),
    EncryptionError(String),
    DecryptionError(String),
    CryptoLibError(String),
    InvalidSignature(String),
}

impl From<SymmetricKeyError> for Error {
    fn from(e: SymmetricKeyError) -> Self {
        Self::SymmetricKeyError(e)
    }
}

impl From<AsymmetricKeyError> for Error {
    fn from(e: AsymmetricKeyError) -> Self {
        Self::AsymmetricKeyError(e)
    }
}

pub type Result<T> = result::Result<T, Error>;
