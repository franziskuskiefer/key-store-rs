use crate::{
    keys::PublicKey,
    secret::Secret,
    types::{
        AeadType, AsymmetricKeyType, Ciphertext, HashType, HpkeKdfType, HpkeKemType, KemOutput,
        Plaintext, PrivateKeyId, Signature, Status, SymmetricKeyType,
    },
    KeyStoreIdentifier, Result,
};

/// The main Key Store trait
pub trait KeyStoreTrait: Send + Sync {
    fn store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>
    where
        Self: Sized;
    fn read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V>
    where
        Self: Sized;
    fn update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()>
    where
        Self: Sized;
    fn delete(&self, k: &impl KeyStoreId) -> Result<()>
    where
        Self: Sized;
}

/// Any value that is stored in the key store must implement this trait.
/// In most cases these are the raw bytes of the object.
pub trait KeyStoreValue {
    fn serialize(&self) -> Result<Vec<u8>>;
    fn deserialize(raw: &mut [u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Any value that is used as key to index values in the key store mut implement
/// this trait.
pub trait KeyStoreId: Eq {
    fn id(&self) -> Result<KeyStoreIdentifier>
    where
        Self: Sized;
}

// === Crypto traits === //

/// Check whether the key store supports certain functionality.
pub trait Supports {
    fn symmetric_key_types(&self) -> Vec<SymmetricKeyType>
    where
        Self: Sized;
    fn asymmetric_key_types(&self) -> Vec<AsymmetricKeyType>
    where
        Self: Sized;
}

/// Generate keys.
pub trait GenerateKeys: Hash {
    fn new_secret(
        &self,
        key_type: SymmetricKeyType,
        status: Status,
        k: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<()>;
    fn new_key_pair(
        &self,
        key_type: AsymmetricKeyType,
        status: Status,
        label: &[u8],
    ) -> Result<(PublicKey, PrivateKeyId)>;
}

/// Hashing
pub trait Hash {
    type StatefulHasher;

    /// Single-shot hash
    fn hash(&self, hash: HashType, data: &[u8]) -> Result<Vec<u8>>;

    /// Get a stateful hasher object for the streaming API.
    fn hasher(&self, hash: HashType) -> Result<Self::StatefulHasher>
    where
        Self: Sized;
}

/// Streaming API for hashing
pub trait Hasher {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finish(&mut self) -> Result<Vec<u8>>;
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
/// Note that his trait only holds a very limited subset of HPKE.
/// Only single-shot, base-mode HPKE is supported for now.
pub trait HpkeSeal {
    /// Encrypt the `payload` to the public key stored for `key_id`.
    fn seal(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, KemOutput)>;

    /// Encrypt the `payload` to the public `key`.
    fn seal_to_pk(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, KemOutput)>;

    /// Encrypt the secret stored for `secret_id` to the public key stored for `key_id`.
    fn seal_secret(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Vec<u8>, KemOutput)>;

    /// Encrypt the secret stored for `secret_id` to the public `key`.
    fn seal_secret_to_pk(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Vec<u8>, KemOutput)>;
}

pub trait HpkeOpen {
    /// Open an HPKE `cipher_text` with the private key of the given `key_id`.
    fn open(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        cipher_text: &Ciphertext,
        kem: &KemOutput,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Plaintext>;
}

/// XXX: We really only need the KEM type here. But hpke-rs needs all of it
pub trait HpkeDerive {
    /// Derive a new HPKE keypair from the secret at `ikm_id`.
    fn derive_key_pair(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        ikm_id: &impl KeyStoreId,
        private_key_id: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<PublicKey>;
}

pub trait Sign {
    fn sign(
        &self,
        key_id: &impl KeyStoreId,
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<Signature>;
}

pub trait Verify {
    fn verify(&self, key_id: &impl KeyStoreId, signature: &Signature, payload: &[u8])
        -> Result<()>;
    fn verify_with_pk(&self, key: &PublicKey, signature: &Signature, payload: &[u8]) -> Result<()>;
}
