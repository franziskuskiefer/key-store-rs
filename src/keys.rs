//! # Public and Private Keys
//!
//! This module defines public and private key types that must be used to interact
//! with the key store.
//!
//! FIXME: trait vs types. What do we really need.

#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use std::convert::{TryFrom, TryInto};

use crate::{
    traits::{private::PrivateKeyStoreValue, KeyStoreValue},
    types::AsymmetricKeyType,
    util::{U16_LEN, U32_LEN},
    Result,
};
use tls_codec::{TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

#[cfg(feature = "serialization")]
pub(crate) use serde::{Deserialize, Serialize};

/// # AsymmetricKeyError
///
/// This error is thrown when an asymmetric key operation fails.
#[derive(Debug, PartialEq, Eq)]
pub enum AsymmetricKeyError {
    /// The key type is not supported.
    InvalidKeyType(usize),

    /// The key serialization is not valid.
    InvalidSerialization,

    /// An error in the underlying crypto library occurred.
    CryptoLibError(String),
}

/// # Public key
///
/// A public key is a byte vector with an associated `AsymmetricKeyType` and an
/// arbitrary label.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Eq, Zeroize, PartialEq, Clone, Debug)]
#[zeroize(drop)]
pub struct PublicKey {
    value: Vec<u8>,
    key_type: AsymmetricKeyType,
    label: Vec<u8>,
}

impl PublicKey {
    pub(crate) fn from(key_type: AsymmetricKeyType, value: &[u8], label: &[u8]) -> Self {
        Self {
            value: value.to_vec(),
            key_type,
            label: label.to_vec(),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn key_type(&self) -> AsymmetricKeyType {
        self.key_type
    }
}

impl KeyStoreValue for PublicKey {}

impl PrivateKeyStoreValue for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            U32_LEN /* value len */ + self.value.len() + U16_LEN /* key type */ + U16_LEN /* label len */ + self.label.len(),
        );
        out.extend((self.value.len() as u32).to_be_bytes().iter());
        out.extend(self.value.iter());
        let key_type: u16 = self.key_type.into();
        out.extend(key_type.to_be_bytes().iter());
        out.extend((self.label.len() as u16).to_be_bytes().iter());
        out.extend(self.label.iter());
        out
    }

    fn deserialize(raw: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let (value_len_bytes, raw) = raw.split_at(U32_LEN);
        let value_len = u32::from_be_bytes(value_len_bytes.try_into().unwrap());
        let (value, raw) = raw.split_at(value_len.try_into().unwrap());
        let (key_type, raw) = raw.split_at(U16_LEN);
        let (label_len_bytes, label) = raw.split_at(U16_LEN);
        if label.len() != u16::from_be_bytes(label_len_bytes.try_into().unwrap()).into() {
            return Err(AsymmetricKeyError::InvalidSerialization.into());
        }
        Ok(Self {
            value: value.to_vec(),
            key_type: AsymmetricKeyType::try_from(u16::from_be_bytes(
                key_type.try_into().unwrap(),
            ))?,
            label: label.to_vec(),
        })
    }
}
