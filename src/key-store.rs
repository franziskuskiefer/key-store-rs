use std::result;

use secret::SymmetricKeyError;

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
    SymmetricKeyError(SymmetricKeyError),
}

impl From<SymmetricKeyError> for Error {
    fn from(e: SymmetricKeyError) -> Self {
        Self::SymmetricKeyError(e)
    }
}

pub type Result<T> = result::Result<T, Error>;
