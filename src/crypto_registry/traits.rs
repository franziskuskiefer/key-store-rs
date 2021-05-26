use std::fmt::Debug;

/// The basic trait implemented by all primitives.
pub trait Algorithm {
    fn get_name() -> String
    where
        Self: Sized;
}

/// A crypto library that wants to register with the `Registry` has to implement
/// this `Provider` trait.
pub trait Provider: Send + Sync + Debug {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn aead(&self, algorithm: &'static str) -> Option<&Box<dyn Aead>>;
    fn digest(&self, algorithm: &'static str) -> Option<&Box<dyn Digest>>;
}

pub type Ciphertext = Vec<u8>;
pub type Tag = Vec<u8>;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInit = 0,
    InvalidAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
    UnsupportedConfig = 4,
    Encrypting = 5,
    Decrypting = 6,
}

pub trait Aead: Algorithm + Send + Sync + Debug {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<dyn Aead>;

    // Nonce and key generation helper.
    fn key_gen(&self) -> Vec<u8>;
    fn key_len(&self) -> usize;
    fn nonce_gen(&self) -> Vec<u8>;
    fn nonce_len(&self) -> usize;

    // Single-shot encryption/decryption.
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        m: &[u8],
    ) -> Result<(Ciphertext, Tag), Error>;
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        c: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, String>;
}

pub trait Digest: Algorithm + Send + Sync + Debug {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<dyn Digest>;

    // Single-shot hash function.
    fn hash(&self, message: &[u8]) -> Vec<u8>;

    // Streaming interface.
    fn update(&mut self, message: &[u8]);
    fn finish(&self, message: &[u8]) -> Vec<u8>;
}
