use crate::{
    secret::Secret,
    traits::{KeyStoreId, KeyStoreTrait, OpenMlsKeyGenerator},
    KeyStore, Result,
};

impl OpenMlsKeyGenerator for KeyStore {
    fn new_secret(&self, k: &impl KeyStoreId, secret_len: usize) -> Result<()> {
        let new_secret = Secret::random(secret_len);
        self.store(k, &new_secret)
    }
}
