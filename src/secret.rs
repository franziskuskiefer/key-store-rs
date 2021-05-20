use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    traits::{private::PrivateKeyStoreValue, KeyStoreValue},
    types::SymmetricKeyType,
    util::{bytes_to_hex, equal_ct},
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

#[derive(Eq, Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    value: Vec<u8>,
    key_type: SymmetricKeyType,
    label: Vec<u8>,
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
        equal_ct(&self.value, &other.value)
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
            bytes_to_hex(&self.label)
        )
    }
}

#[cfg(feature = "hazmat")]
impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret {{\n  value: {}\n  key_type: {:?}\n label: {}\n}}",
            bytes_to_hex(&self.value),
            self.key_type,
            bytes_to_hex(&self.label)
        )
    }
}

impl Secret {
    #[cfg(features = "random")]
    pub(crate) fn random(len: usize, key_type: SymmetricKeyType, label: &[u8]) -> Self {
        let mut value = vec![0u8; len];
        OsRng.fill_bytes(&mut value);
        Self {
            value,
            key_type,
            label: label.to_vec(),
        }
    }

    pub(crate) fn random_bor<T: CryptoRng + RngCore>(
        randomness: &mut T,
        len: usize,
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Self {
        let mut value = vec![0u8; len];
        randomness.fill_bytes(&mut value);
        Self {
            value,
            key_type,
            label: label.to_vec(),
        }
    }

    pub(crate) fn try_from_slice(
        b: &[u8],
        key_type: SymmetricKeyType,
        label: &[u8],
    ) -> Result<Self> {
        Self::try_from(b.to_vec(), key_type, label)
    }

    pub(crate) fn try_from(b: Vec<u8>, key_type: SymmetricKeyType, label: &[u8]) -> Result<Self> {
        if b.len() != key_type.len() {
            return Err(Error::SymmetricKeyError(SymmetricKeyError::InvalidLength(
                b.len(),
                key_type.len(),
            )));
        }
        Ok(Self {
            value: b,
            key_type,
            label: label.to_vec(),
        })
    }
}

const U16_LEN: usize = std::mem::size_of::<u16>();
const U32_LEN: usize = std::mem::size_of::<u32>();

impl KeyStoreValue for Secret {}

impl PrivateKeyStoreValue for Secret {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            U32_LEN /* value len */ + self.value.len() + U32_LEN /* key type */ + U16_LEN /* label len */ + self.label.len(),
        );
        out.extend((self.value.len() as u32).to_be_bytes().iter());
        out.extend(self.value.iter());
        let key_type: u32 = self.key_type.into();
        out.extend(key_type.to_be_bytes().iter());
        out.extend((self.label.len() as u16).to_be_bytes().iter());
        out.extend(self.label.iter());
        out
    }

    fn deserialize(raw: &[u8]) -> Result<Self> {
        let (value_len_bytes, raw) = raw.split_at(U32_LEN);
        let value_len = u32::from_be_bytes(value_len_bytes.try_into().unwrap());
        let (value, raw) = raw.split_at(value_len.try_into().unwrap());
        let (key_type, raw) = raw.split_at(U32_LEN);
        let (label_len_bytes, label) = raw.split_at(U16_LEN);
        if label.len() != u16::from_be_bytes(label_len_bytes.try_into().unwrap()).into() {
            return Err(SymmetricKeyError::InvalidSerialization.into());
        }

        Ok(Self {
            value: value.to_vec(),
            key_type: SymmetricKeyType::try_from(u32::from_be_bytes(key_type.try_into().unwrap()))?,
            label: label.to_vec(),
        })
    }
}
