use evercrypt::prelude::get_random_vec;
use zeroize::Zeroize;

use crate::traits::KeyStoreValue;

#[derive(Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub(crate) struct Secret {
    value: Vec<u8>,
}

impl From<&[u8]> for Secret {
    fn from(b: &[u8]) -> Self {
        Self { value: b.to_vec() }
    }
}

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self { value }
    }
}

impl Secret {
    pub(crate) fn random(len: usize) -> Self {
        Self {
            value: get_random_vec(len),
        }
    }
}

impl KeyStoreValue for Secret {
    fn serialize(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn deserialize(raw: &[u8]) -> Self {
        Self {
            value: raw.to_vec(),
        }
    }
}
