#[cfg(feature = "openmls_keys")]
use openmls::prelude::{CiphersuiteName, CredentialType, Extension, SignatureScheme};

use crate::{KeyStoreIdentifier, Result};

/// The main Key Store trait
pub trait KeyStoreTrait {
    fn store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>;
    fn read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V>;
    fn update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>;
    fn delete(&self, k: &impl KeyStoreId) -> Result<()>;
}

/// Any value that is stored in the key store must implement this trait.
/// In most cases these are the raw bytes of the object.
pub trait KeyStoreValue {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(raw: &[u8]) -> Self
    where
        Self: Sized;
}

/// Any value that is used as key to index values in the key store mut implement
/// this trait.
pub trait KeyStoreId: Eq {
    fn id(&self) -> KeyStoreIdentifier;
}

/// Generate OpenMLS secrets, credential bundles, and key package bundles.
/// This requires the `openmls_keys` feature to be enabled.
#[cfg(feature = "openmls_keys")]
pub trait OpenMlsKeyGenerator {
    fn new_secret(&self, k: &impl KeyStoreId, secret_len: usize) -> Result<()>;
    fn new_credential_bundle(
        &self,
        _k: &impl KeyStoreId,
        _c_type: CredentialType,
        _scheme: SignatureScheme,
    ) {
        todo!();
    }
    fn new_key_package_bundle(
        &self,
        _k: &impl KeyStoreId,
        _credential_id: impl KeyStoreId,
        _ciphersuite: CiphersuiteName,
        _extensions: &[Box<dyn Extension>],
    ) {
        todo!();
    }
}
