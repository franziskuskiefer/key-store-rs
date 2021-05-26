use std::{result, sync::PoisonError};

use keys::AsymmetricKeyError;
use secret::SymmetricKeyError;
use types::{AsymmetricKeyType, SymmetricKeyType};

pub mod keys;
pub mod secret;
pub mod traits;
pub mod types;
pub mod crypto_registry;

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
    MutexError(String),
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

impl<Guard> From<PoisonError<Guard>> for Error {
    fn from(e: PoisonError<Guard>) -> Self {
        Self::MutexError(format!("Sync poison error {}", e))
    }
}

pub type Result<T> = result::Result<T, Error>;
