use crate::{
    keys::PublicKey,
    secret::Secret,
    types::{
        AeadType, AsymmetricKeyType, Ciphertext, HashType, KemOutput, Plaintext, Signature,
        SymmetricKeyType,
    },
    KeyStoreIdentifier, Result,
};

/// The main Key Store trait
pub trait KeyStoreTrait {
    fn store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>;
    fn read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V>;
    fn update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>;
    fn delete(&self, k: &impl KeyStoreId) -> Result<()>;
}

/// This private module is used to hide functionality of public traits.
pub(crate) mod private {
    use crate::Result;

    #[doc(hidden)]
    pub trait PrivateKeyStoreValue {
        fn serialize(&self) -> Vec<u8>;
        fn deserialize(raw: &[u8]) -> Result<Self>
        where
            Self: Sized;
    }
}

/// Any value that is stored in the key store must implement this trait.
/// In most cases these are the raw bytes of the object.
pub trait KeyStoreValue: private::PrivateKeyStoreValue {}

/// Any value that is used as key to index values in the key store mut implement
/// this trait.
pub trait KeyStoreId: Eq {
    fn id(&self) -> KeyStoreIdentifier;
}

// === Crypto traits === //

/// Check whether the key store supports certain functionality.
pub trait Supports {
    fn symmetric_key_types(&self) -> Vec<SymmetricKeyType>;
    fn asymmetric_key_types(&self) -> Vec<AsymmetricKeyType>;
}

/// Generate keys.
pub trait GenerateKeys {
    fn new_secret(
        &self,
        key_type: SymmetricKeyType,
        k: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<()>;
    fn new_key_pair(
        &self,
        key_type: AsymmetricKeyType,
        k: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<PublicKey>;
}

/// HKDF
pub trait HkdfDerive {
    /// HKDF extract
    /// Panics if not implemented.
    /// This can also be used to compute an HMAC.
    /// ☣️ **NOTE** that this returns secret key material.
    fn extract(&self, _hash: HashType, _ikm: &impl KeyStoreId, _salt: &[u8]) -> Result<Secret> {
        unimplemented!();
    }

    /// HKDF expand
    /// Panics if not implemented.
    /// ☣️ **NOTE** that this returns secret key material.
    fn expand(
        &self,
        _hash: HashType,
        _prk: &impl KeyStoreId,
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Secret> {
        unimplemented!();
    }

    /// HKDF
    /// Compute HKDF on the input and store it with the `okm` id.
    /// This is the only function that must be implemented.
    fn hkdf(
        &self,
        hash: HashType,
        ikm: &impl KeyStoreId,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &impl KeyStoreId,
    ) -> Result<()>;

    /// HKDF
    /// Panics if not implemented.
    /// ☣️ **NOTE** that this returns secret key material.
    fn hkdf_export(
        &self,
        _hash: HashType,
        _ikm: &impl KeyStoreId,
        _salt: &[u8],
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Secret> {
        unimplemented!();
    }
}

/// AEAD
pub trait Seal {
    fn seal(
        &self,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Ciphertext>;
}
pub trait Open {
    fn open(
        &self,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        cipher_text: &Ciphertext,
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext>;
}

/// HPKE
pub trait Hpke<HpkeImpl> {
    /// Encrypt the `payload` to the public key stored for `key_id`.
    fn seal(
        hpke: HpkeImpl,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Ciphertext, KemOutput)>;

    /// Encrypt the `payload` to the public `key`.
    fn seal_to_pk(
        hpke: HpkeImpl,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Ciphertext, KemOutput)>;

    /// Encrypt the secret stored for `secret_id` to the public key stored for `key_id`.
    fn seal_secret(
        hpke: HpkeImpl,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Ciphertext, KemOutput)>;

    /// Encrypt the secret stored for `secret_id` to the public `key`.
    fn seal_secret_to_pk(
        hpke: HpkeImpl,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Ciphertext, KemOutput)>;

    /// Open an HPKE `cipher_text` with the private key of the given `key_id`.
    fn open(
        hpke: HpkeImpl,
        key_id: &impl KeyStoreId,
        cipher_text: &Ciphertext,
        kem: &KemOutput,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Plaintext>;

    /// Derive a new HPKE keypair from the secret at `ikm_id`.
    fn derive_key_pair(hpke: HpkeImpl, ikm_id: &impl KeyStoreId) -> Result<()>;
}

pub trait Sign {
    fn sign(key_id: &impl KeyStoreId, payload: &[u8]) -> Result<Signature>;
}

pub trait Verify {
    fn verify(key_id: &impl KeyStoreId, signature: &Signature, payload: &[u8]) -> Result<()>;
    fn verify_with_pk(key: &PublicKey, signature: &Signature, payload: &[u8]) -> Result<()>;
}
