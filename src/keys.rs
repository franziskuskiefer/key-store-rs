use std::convert::{TryFrom, TryInto};

use crate::{
    traits::{private::PrivateKeyStoreValue, KeyStoreValue},
    types::AsymmetricKeyType,
    util::{equal_ct, U16_LEN, U32_LEN},
    Result,
};
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub enum AsymmetricKeyError {
    InvalidKeyType(usize),
    InvalidSerialization,
    CryptoLibError(String),
}

#[derive(Eq, Zeroize, PartialEq, Clone)]
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
}

impl KeyStoreValue for PublicKey {}

impl PrivateKeyStoreValue for PublicKey {
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

    fn deserialize(raw: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let (value_len_bytes, raw) = raw.split_at(U32_LEN);
        let value_len = u32::from_be_bytes(value_len_bytes.try_into().unwrap());
        let (value, raw) = raw.split_at(value_len.try_into().unwrap());
        let (key_type, raw) = raw.split_at(U32_LEN);
        let (label_len_bytes, label) = raw.split_at(U16_LEN);
        if label.len() != u16::from_be_bytes(label_len_bytes.try_into().unwrap()).into() {
            return Err(AsymmetricKeyError::InvalidSerialization.into());
        }
        Ok(Self {
            value: value.to_vec(),
            key_type: AsymmetricKeyType::try_from(u32::from_be_bytes(
                key_type.try_into().unwrap(),
            ))?,
            label: label.to_vec(),
        })
    }
}

#[derive(Eq, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey {
    value: Vec<u8>,
    key_type: AsymmetricKeyType,
    label: Vec<u8>,
    public_key: Option<PublicKey>,
}

impl PrivateKey {
    pub(crate) fn from<'a>(
        key_type: AsymmetricKeyType,
        value: &[u8],
        label: &[u8],
        public_key: impl Into<Option<&'a PublicKey>>,
    ) -> Self {
        Self {
            value: value.to_vec(),
            key_type,
            label: label.to_vec(),
            public_key: public_key.into().cloned(),
        }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        if self.key_type != other.key_type {
            log::error!("The two keys have different key types.");
            return false;
        }
        if self.label != other.label {
            log::error!("The two keys have different labels.");
            return false;
        }
        if self.value.len() != other.value.len() {
            log::error!("The two keys have different lengths.");
            return false;
        }
        equal_ct(&self.value, &other.value)
    }
}

impl KeyStoreValue for PrivateKey {}

impl PrivateKeyStoreValue for PrivateKey {
    fn serialize(&self) -> Vec<u8> {
        let serialized_public_key = self.public_key.as_ref().map(|pk| pk.serialize());
        let serialized_public_key_len = serialized_public_key.as_ref().map_or(0, |pk| pk.len());
        let mut out = Vec::with_capacity(
            U32_LEN /* value len */ + self.value.len() + U32_LEN /* key type */ + U16_LEN /* label len */ + self.label.len() + 1 /* Option */ + serialized_public_key_len,
        );
        out.extend((self.value.len() as u32).to_be_bytes().iter());
        out.extend(self.value.iter());
        let key_type: u32 = self.key_type.into();
        out.extend(key_type.to_be_bytes().iter());
        out.extend((self.label.len() as u16).to_be_bytes().iter());
        out.extend(self.label.iter());
        out.push(match self.public_key {
            Some(_) => 1,
            None => 0,
        });
        if let Some(mut pk) = serialized_public_key {
            out.append(&mut pk);
        }
        out
    }

    fn deserialize(raw: &[u8]) -> Result<Self> {
        let (value_len_bytes, raw) = raw.split_at(U32_LEN);
        let value_len = u32::from_be_bytes(value_len_bytes.try_into().unwrap());
        let (value, raw) = raw.split_at(value_len.try_into().unwrap());
        let (key_type, raw) = raw.split_at(U32_LEN);
        let (label_len_bytes, label) = raw.split_at(U16_LEN);
        if label.len() != u16::from_be_bytes(label_len_bytes.try_into().unwrap()).into() {
            return Err(AsymmetricKeyError::InvalidSerialization.into());
        }
        let (public_key_op, raw) = raw.split_at(1);
        let public_key = if public_key_op[0] == 1 {
            Some(PublicKey::deserialize(raw)?)
        } else {
            None
        };

        Ok(Self {
            value: value.to_vec(),
            key_type: AsymmetricKeyType::try_from(u32::from_be_bytes(
                key_type.try_into().unwrap(),
            ))?,
            label: label.to_vec(),
            public_key,
        })
    }
}
