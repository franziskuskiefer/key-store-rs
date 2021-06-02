use std::{
    convert::{TryFrom},
    io::Write,
    usize,
};

use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::{
    keys::AsymmetricKeyError,
    secret::SymmetricKeyError,
    traits::{KeyStoreId, KeyStoreValue},
    util::U32_LEN,
    Error, KeyStoreIdentifier, Result, KEY_STORE_ID_LEN,
};

/// Signature key types.
/// This uses the TLS IANA parameters
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
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
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
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

/// Asymmetric key types.
/// This can either be a signature key or a KEM key.
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
pub enum AsymmetricKeyType {
    SignatureKey(SignatureKeyType),
    KemKey(KemKeyType),
}

impl From<SignatureKeyType> for AsymmetricKeyType {
    fn from(t: SignatureKeyType) -> Self {
        Self::SignatureKey(t)
    }
}

impl From<KemKeyType> for AsymmetricKeyType {
    fn from(t: KemKeyType) -> Self {
        Self::KemKey(t)
    }
}

impl tls_codec::Serialize for AsymmetricKeyType {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), tls_codec::Error> {
        writer.write(match self {
            // XXX: pull out the outer type ser/de
            AsymmetricKeyType::SignatureKey(_) => &[0],
            AsymmetricKeyType::KemKey(_) => &[1],
        })?;
        match self {
            AsymmetricKeyType::SignatureKey(k) => k.tls_serialize(writer),
            AsymmetricKeyType::KemKey(k) => k.tls_serialize(writer),
        }
    }
}

impl Deserialize for AsymmetricKeyType {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> core::result::Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut outer_type = [0u8; 1];
        bytes.read_exact(&mut outer_type)?;
        match u8::from_be_bytes(outer_type) {
            0 => Ok(Self::SignatureKey(SignatureKeyType::tls_deserialize(
                bytes,
            )?)),
            1 => Ok(Self::KemKey(KemKeyType::tls_deserialize(bytes)?)),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "Unknown asymmetric outer key type {:?}",
                outer_type
            ))),
        }
    }
}

impl TlsSize for AsymmetricKeyType {
    fn serialized_len(&self) -> usize {
        1 + match self {
            AsymmetricKeyType::SignatureKey(k) => k.serialized_len(),
            AsymmetricKeyType::KemKey(k) => k.serialized_len(),
        }
    }
}

impl TryFrom<u16> for SignatureKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0807 => Ok(SignatureKeyType::Ed25519),
            0x0808 => Ok(SignatureKeyType::Ed448),
            0x0403 => Ok(SignatureKeyType::EcdsaP256Sha256),
            0x0603 => Ok(SignatureKeyType::EcdsaP521Sha512),
            _ => Err(AsymmetricKeyError::InvalidKeyType(value as usize)),
        }
    }
}

impl TryFrom<HpkeKemType> for KemKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(kem: HpkeKemType) -> std::result::Result<Self, Self::Error> {
        match kem {
            HpkeKemType::DhKemP256 => Ok(Self::P256),
            HpkeKemType::DhKem25519 => Ok(Self::X25519),
            HpkeKemType::DhKem448 => Ok(Self::X448),
            HpkeKemType::DhKemP384 => Ok(Self::P384),
            HpkeKemType::DhKemP521 => Ok(Self::P521),
        }
    }
}

impl TryFrom<HpkeKemType> for AsymmetricKeyType {
    type Error = AsymmetricKeyError;

    fn try_from(kem: HpkeKemType) -> std::result::Result<Self, Self::Error> {
        Ok(Self::KemKey(KemKeyType::try_from(kem)?))
    }
}

impl Into<u16> for SignatureKeyType {
    fn into(self) -> u16 {
        self as u16
    }
}

impl Into<u16> for KemKeyType {
    fn into(self) -> u16 {
        self as u16
    }
}

/// Asymmetric key types
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
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

impl TlsSize for SymmetricKeyType {
    #[inline]
    fn serialized_len(&self) -> usize {
        U32_LEN
    }
}

impl Serialize for SymmetricKeyType {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), tls_codec::Error> {
        let self_u32: u32 = self.into();
        self_u32.tls_serialize(writer)
    }
}

impl Deserialize for SymmetricKeyType {
    fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> core::result::Result<Self, tls_codec::Error> {
        let mut self_bytes = [0u8; U32_LEN];
        bytes.read_exact(&mut self_bytes)?;
        Self::try_from(u32::from_be_bytes(self_bytes)).map_err(|_e| tls_codec::Error::InvalidInput)
    }
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

impl Into<u32> for &SymmetricKeyType {
    fn into(self) -> u32 {
        (*self).into()
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

#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, PartialEq, Eq, Zeroize, Clone, Copy)]
#[repr(u16)]
/// Hash types
pub enum HashType {
    Sha1,
    Sha2_224,
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

#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    value: Vec<u8>,
    hash_type: Option<HashType>,
}

impl Signature {
    pub fn new(value: Vec<u8>, hash_type: impl Into<Option<HashType>>) -> Self {
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

/// The key store identifier for private keys.
/// Note that you can define your own private key identifiers and pass them in
/// when generating new key pairs. This is a default implementation for any
/// implementation that doesn't which to use their own identifiers or wants to
/// have it depend on the public key.
pub type PrivateKeyId = Vec<u8>;

impl KeyStoreId for Vec<u8> {
    fn id(&self) -> Result<KeyStoreIdentifier> {
        if self.len() != KEY_STORE_ID_LEN {
            return Err(Error::InvalidKeyStoreId(format!(
                "Can't convert a {} byte vector into a {} byte vector.",
                self.len(),
                KEY_STORE_ID_LEN
            )));
        }
        let mut id = [0u8; KEY_STORE_ID_LEN];
        id.clone_from_slice(&self);
        Ok(KeyStoreIdentifier(id))
    }
}

impl KeyStoreId for [u8; KEY_STORE_ID_LEN] {
    fn id(&self) -> Result<KeyStoreIdentifier> {
        Ok(KeyStoreIdentifier(self.clone()))
    }
}

/// The status of a value in the key store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Values marked with this can be extracted from the key store.
    Extractable = 1,

    /// Values marked as hidden can not be extracted from the key store.
    Hidden = 2,

    /// Unconfirmed values must be confirmed before they are permanently stored.
    /// Note that unconfirmed values must be persisted as well, but may be dropped
    /// in bulk or can't be used for certain operations.
    UnconfirmedExtractable = 3,

    /// Same as `UnconfirmedExtractable` but the value can not be extracted.
    UnconfirmedHidden = 4,
}

impl TryFrom<u8> for Status {
    type Error = crate::Error;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Extractable,
            2 => Self::Hidden,
            3 => Self::UnconfirmedExtractable,
            4 => Self::UnconfirmedHidden,
            _ => return Err(Error::InvalidStatus(value)),
        })
    }
}

impl KeyStoreValue for Status {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![*self as u8])
    }

    fn deserialize(raw: &mut [u8]) -> Result<Self> {
        if raw.len() < 1 {
            return Err(Error::InvalidStatus(u8::MAX));
        }
        Self::try_from(raw[0])
    }
}
