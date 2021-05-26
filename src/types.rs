use std::{
    convert::{TryFrom, TryInto},
    usize,
};

#[cfg(feature = "serialization")]
pub(crate) use serde::{Deserialize, Serialize};

use tls_codec::{TlsDeserialize, TlsSerialize};
use zeroize::Zeroize;

use crate::{
    crypto_registry::{algorithms::SHA2_256, REGISTRY},
    keys::AsymmetricKeyError,
    secret::SymmetricKeyError,
    traits::KeyStoreId,
    KeyStoreIdentifier, Result,
};

/// Asymmetric key types
/// Note that it is not possible to use the same key for different operations.
/// If a key should be used for two different operations, it must be stored for
/// each type separately.
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum AsymmetricKeyType {
    /// ECDH Curve25519 key
    X25519 = 0,

    /// EdDSA Curve25519 key
    Ed25519 = 1,

    /// EdDSA Curve448 key
    Ed448 = 2,

    /// ECDH NIST P256 key
    P256 = 3,

    /// ECDSA NIST P256 key with SHA 256
    EcdsaP256Sha256 = 4,

    /// ECDSA NIST P521 key with SHA 512
    EcdsaP521Sha512 = 5,
}

/// Signature key types.
/// This uses the TLS IANA parameters
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum SignatureKeyType {
    /// EdDSA Curve25519 key
    Ed25519 = 0x0807,

    /// EdDSA Curve448 key
    Ed448 = 0x0808,

    /// ECDSA NIST P256 key with SHA 256 (ecdsa_secp256r1_sha256)
    EcdsaP256Sha256 = 0x0403,

    /// ECDSA NIST P521 key with SHA 512 (ecdsa_secp521r1_sha512)
    EcdsaP521Sha512 = 0x0603,
}

/// KEM key types.
/// This uses the TLS IANA parameters
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
pub enum KemKeyType {
    /// ECDH Curve25519 key
    X25519 = 29,

    /// ECDH Curve25519 key
    X448 = 30,

    /// ECDH NIST P256 key (secp256r1)
    P256 = 23,

    /// ECDH NIST P384 key (secp384r1)
    P384 = 24,

    /// ECDH NIST P521 key (secp521r1)
    P521 = 25,
}

pub enum AsymmetricKeyType2 {
    SignatureKey(SignatureKeyType),
    KemKey(KemKeyType),
}

impl TryFrom<u16> for AsymmetricKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AsymmetricKeyType::X25519),
            1 => Ok(AsymmetricKeyType::Ed25519),
            2 => Ok(AsymmetricKeyType::Ed448),
            3 => Ok(AsymmetricKeyType::P256),
            4 => Ok(AsymmetricKeyType::EcdsaP256Sha256),
            5 => Ok(AsymmetricKeyType::EcdsaP521Sha512),
            _ => Err(AsymmetricKeyError::InvalidKeyType(value as usize)),
        }
    }
}

impl TryFrom<HpkeKemType> for AsymmetricKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(kem: HpkeKemType) -> std::result::Result<Self, Self::Error> {
        match kem {
            HpkeKemType::DhKemP256 => Ok(Self::P256),
            HpkeKemType::DhKem25519 => Ok(Self::X25519),
            HpkeKemType::DhKem448 | HpkeKemType::DhKemP384 | HpkeKemType::DhKemP521 => {
                Err(AsymmetricKeyError::InvalidKeyType(usize::MAX))
            }
        }
    }
}

impl Into<u16> for AsymmetricKeyType {
    fn into(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
/// Asymmetric key types
pub enum SymmetricKeyType {
    /// An AES 128 secret
    Aes128,

    /// An AES 256 secret
    Aes256,

    /// A ChaCha20 secret
    ChaCha20,

    /// A generic secret type for a secret of a given length.
    Any(u16),
}

impl SymmetricKeyType {
    /// Get the length of the secret.
    pub(crate) const fn len(&self) -> usize {
        match self {
            SymmetricKeyType::Aes128 => 16,
            SymmetricKeyType::Aes256 => 32,
            SymmetricKeyType::ChaCha20 => 32,
            SymmetricKeyType::Any(l) => *l as usize,
        }
    }
}

impl TryFrom<u32> for SymmetricKeyType {
    type Error = SymmetricKeyError;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value & 0xFFFF {
            0 => Ok(SymmetricKeyType::Aes128),
            1 => Ok(SymmetricKeyType::Aes256),
            2 => Ok(SymmetricKeyType::ChaCha20),
            3 => Ok(SymmetricKeyType::Any((value >> 16) as u16)),
            _ => Err(SymmetricKeyError::InvalidKeyType(value as usize)),
        }
    }
}

impl Into<u32> for SymmetricKeyType {
    fn into(self) -> u32 {
        match self {
            SymmetricKeyType::Aes128 => 0,
            SymmetricKeyType::Aes256 => 1,
            SymmetricKeyType::ChaCha20 => 2,
            SymmetricKeyType::Any(l) => 3u32 | (u32::from(l) << 16),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// HPKE Export-only
    Export = 0xFFFF,
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// Hash types
pub enum HashType {
    Sha1,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// KEM HPKE types
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,
}

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// KDF HPKE types
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

pub struct Ciphertext {
    ct: Vec<u8>,
    tag: Vec<u8>,
}

impl Ciphertext {
    pub(crate) fn new(ct: Vec<u8>, tag: Vec<u8>) -> Self {
        Self { ct, tag }
    }
    pub fn cipher_text(&self) -> &[u8] {
        &self.ct
    }
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }
}

pub struct Plaintext {
    pt: Vec<u8>,
}

impl Plaintext {
    pub(crate) fn new(pt: Vec<u8>) -> Self {
        Self { pt }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.pt
    }
}

pub struct KemOutput {
    value: Vec<u8>,
}

impl KemOutput {
    pub(crate) fn new(value: Vec<u8>) -> Self {
        Self { value }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

pub struct Signature {
    value: Vec<u8>,
    hash_type: Option<HashType>,
}

impl Signature {
    pub(crate) fn new(value: Vec<u8>, hash_type: impl Into<Option<HashType>>) -> Self {
        Self {
            value,
            hash_type: hash_type.into(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub fn hash_type(&self) -> Option<HashType> {
        self.hash_type
    }
}

/// The key store identifier for private keys
#[derive(Debug, PartialEq, Eq)]
pub struct PrivateKeyId {
    label: Vec<u8>,
    pk: Vec<u8>,
}

impl PrivateKeyId {
    pub fn new(label: &[u8], pk: &[u8]) -> Self {
        Self {
            label: label.to_vec(),
            pk: pk.to_vec(),
        }
    }
}

impl KeyStoreId for PrivateKeyId {
    fn id(&self) -> Result<KeyStoreIdentifier> {
        let mut sha256 = REGISTRY.digest(SHA2_256).unwrap();
        sha256.update(&self.label);
        sha256.update(&self.pk);
        Ok(KeyStoreIdentifier(sha256.finish(&[]).try_into().unwrap()))
    }
}
