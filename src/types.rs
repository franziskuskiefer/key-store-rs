use std::{convert::TryFrom, usize};

use zeroize::Zeroize;

use crate::{keys::AsymmetricKeyError, secret::SymmetricKeyError};

#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
/// Asymmetric key types
/// Note that it is not possible to use the same key for different operations.
/// If a key should be used for two different operations, it must be stored for
/// each type separately.
pub enum AsymmetricKeyType {
    /// ECDH Curve25519 key
    X25519,

    /// EdDSA Curve25519 key
    Ed25519,

    /// EdDSA Curve448 key
    Ed448,

    /// ECDH NIST P256 key
    P256,

    /// ECDSA NIST P256 key with SHA 256
    EcdsaP256Sha256,

    /// ECDSA NIST P521 key with SHA 512
    EcdsaP521Sha512,
}

impl TryFrom<u32> for AsymmetricKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
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

impl Into<u32> for AsymmetricKeyType {
    fn into(self) -> u32 {
        match self {
            AsymmetricKeyType::X25519 => 0,
            AsymmetricKeyType::Ed25519 => 1,
            AsymmetricKeyType::Ed448 => 2,
            AsymmetricKeyType::P256 => 3,
            AsymmetricKeyType::EcdsaP256Sha256 => 4,
            AsymmetricKeyType::EcdsaP521Sha512 => 5,
        }
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

    fn try_from(value: u32) -> Result<Self, Self::Error> {
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
    /// AES-GCM 128
    Aes128Gcm,

    /// AES-GCM 256
    Aes256Gcm,

    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
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

pub struct Signature {
    value: Vec<u8>,
}
