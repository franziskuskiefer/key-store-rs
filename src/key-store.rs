use std::{result, sync::PoisonError};

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

pub const KEY_STORE_ID_LEN: usize = 32;
#[derive(PartialEq, Eq, Debug)]
pub struct KeyStoreIdentifier([u8; KEY_STORE_ID_LEN]);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    WriteError,
    EncodingError(String),
    ReadError,
    ForbiddenExtraction,
    DecodingError(String),
    DigestError(String),
    UpdateError,
    DeleteError,
    InvalidKeyStoreId(String),
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
    InvalidStatus(u8),
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

impl From<tls_codec::Error> for Error {
    fn from(e: tls_codec::Error) -> Self {
        match &e {
            tls_codec::Error::EncodingError => {
                Self::EncodingError(format!("TLS encoding error: {:?}", e))
            }
            tls_codec::Error::InvalidVectorLength => {
                Self::DecodingError(format!("TLS decoding error: {:?}", e))
            }
            tls_codec::Error::InvalidInput => {
                Self::DecodingError(format!("TLS decoding error: {:?}", e))
            }
            tls_codec::Error::DecodingError(description) => {
                Self::DecodingError(format!("TLS decoding error: {:?} - {}", e, description))
            }
            tls_codec::Error::EndOfStream => Self::DecodingError(format!(
                "TLS decoding error (premature end of stream): {:?}",
                e
            )),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
