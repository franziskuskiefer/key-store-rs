#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use tls_codec::{Deserialize, SecretTlsVecU16, Serialize, TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

use crate::{
    keys::PublicKey, traits::KeyStoreValue, types::AsymmetricKeyType, util::equal_ct, Result,
};

/// # Private key
///
/// A private key is a byte vector with an associated `AsymmetricKeyType` and an
/// arbitrary label.
/// Optionally the public key can be stored alongside the private key.
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Eq, Zeroize, TlsSerialize, TlsDeserialize)]
#[zeroize(drop)]
pub struct PrivateKey {
    value: SecretTlsVecU16<u8>,
    key_type: AsymmetricKeyType,
    label: SecretTlsVecU16<u8>,
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
            value: value.to_vec().into(),
            key_type,
            label: label.to_vec().into(),
            public_key: public_key.into().cloned(),
        }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
    pub(crate) fn key_type(&self) -> AsymmetricKeyType {
        self.key_type
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
        equal_ct(self.value.as_slice(), other.value.as_slice())
    }
}

impl KeyStoreValue for PrivateKey {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.tls_serialize_detached().unwrap())
    }

    fn deserialize(raw: &mut [u8]) -> Result<Self> {
        // XXX: can we do this without copy please?
        Ok(Self::tls_deserialize(&mut raw.as_ref()).unwrap())
    }
}
