use std::{array::TryFromSliceError, fmt::Debug};

use rand::{CryptoRng, RngCore};
use tls_codec::{Deserialize, SecretTlsVecU16, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

use crate::{
    traits::{KeyStoreValue},
    types::SymmetricKeyType,
    util::{bytes_to_hex, equal_ct, U16_LEN, U32_LEN},
    Error, Result,
};

#[derive(Debug, PartialEq, Eq)]
pub enum SymmetricKeyError {
    InvalidLength(usize, usize),
    InvalidArrayConversion(String),
    InvalidKeyType(usize),
    InvalidSerialization,
}

impl From<TryFromSliceError> for SymmetricKeyError {
    fn from(e: TryFromSliceError) -> Self {
        Self::InvalidArrayConversion(format!("{}", e))
    }
}

#[derive(Eq, Zeroize, TlsDeserialize, TlsSerialize)]
#[zeroize(drop)]
pub struct Secret {
    value: SecretTlsVecU16<u8>,
    key_type: SymmetricKeyType,
    label: SecretTlsVecU16<u8>,
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        if self.key_type != other.key_type {
            log::error!("The two secrets have different key types.");
            return false;
        }
        if self.label != other.label {
            log::error!("The two secrets have different labels.");
            return false;
        }
        if self.value.len() != other.value.len() {
            log::error!("The two secrets have different lengths.");
            return false;
        }
        equal_ct(self.value.as_slice(), other.value.as_slice())
    }
}

#[cfg(not(feature = "hazmat"))]
impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret {{\n  value: {}\n  key_type: {:?}\n label: {}\n}}",
            &"***",
            self.key_type,
            bytes_to_hex(self.label.as_slice())
        )
    }
}

#[cfg(feature = "hazmat")]
impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret {{\n  value: {}\n  key_type: {:?}\n label: {}\n}}",
            bytes_to_hex(self.value.as_slice()),
            self.key_type,
            bytes_to_hex(self.label.as_slice())
        )
    }
}

impl Secret {
    #[cfg(features = "random")]
    pub(crate) fn random(key_type: SymmetricKeyType, label: &[u8]) -> Self {
        let mut value = vec![0u8; key_type.len()];
        OsRng.fill_bytes(&mut value);
        Self {
            value,
            key_type,
            label: label.into(),
        }
    }

    pub(crate) fn random_bor<T: CryptoRng + RngCore>(
        randomness: &mut T,
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Self {
        let mut value = vec![0u8; key_type.len()];
        randomness.fill_bytes(&mut value);
        Self {
            value: value.into(),
            key_type,
            label: label.into(),
        }
    }

    /// Get an all-zero secret
    pub(crate) fn zero(key_type: SymmetricKeyType, label: &[u8]) -> Result<Self> {
        Self::try_from(vec![0u8; key_type.len()], key_type, label)
    }

    pub(crate) fn try_from_slice(
        b: &[u8],
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Result<Self> {
        Self::try_from(b.into(), key_type, label)
    }

    // XXX: do we really want this?
    pub fn try_from(b: Vec<u8>, key_type: SymmetricKeyType, label: &[u8]) -> Result<Self> {
        if b.len() != key_type.len() {
            return Err(Error::SymmetricKeyError(SymmetricKeyError::InvalidLength(
                b.len(),
                key_type.len(),
            )));
        }
        Ok(Self {
            value: b.into(),
            key_type,
            label: label.into(),
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl KeyStoreValue for Secret {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.tls_serialize_detached().unwrap())
    }

    fn deserialize(raw: &mut [u8]) -> Result<Self> {
        // XXX: can we do this without copy please?
        Ok(Self::tls_deserialize(&mut raw.as_ref()).unwrap())
    }
}
