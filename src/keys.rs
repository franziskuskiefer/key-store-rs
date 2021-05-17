use crate::{
    traits::{private::PrivateKeyStoreValue},
    types::AsymmetricKeyType,
    util::equal_ct,
    Result,
};
use zeroize::Zeroize;

#[derive(Eq, Zeroize, PartialEq)]
#[zeroize(drop)]
pub struct PublicKey {
    value: Vec<u8>,
    key_type: AsymmetricKeyType,
    label: Vec<u8>,
}

#[derive(Eq, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey {
    value: Vec<u8>,
    key_type: AsymmetricKeyType,
    label: Vec<u8>,
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

impl PrivateKeyStoreValue for PrivateKey {
    fn serialize(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn deserialize(_raw: &[u8]) -> Result<Self> {
        unimplemented!("Secrets can't be deserialized. Please use `UntypedPrivateKey` and `try_from_untyped_secret`.")
    }
}
