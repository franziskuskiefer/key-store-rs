use std::{any::Any, collections::HashMap};

use evercrypt::prelude::*;
use key_store::crypto_registry::{
    base_provider::BaseProvider,
    traits::{Aead, Algorithm, Digest, Error},
    Registry,
};

#[test]
pub fn init() {
    let registry = Registry::new();
    let supported = registry.supports("some algorithm");
    assert_eq!(false, supported);
}

pub struct EvercryptProvider {}

macro_rules! implement_aead {
    ($provider_name:ident, $string_id:literal, $mode:expr) => {
        #[derive(Debug)]
        pub struct $provider_name {
            mode: AeadMode,
            nonce_len: usize,
        }

        impl Algorithm for $provider_name {
            fn name() -> String {
                $string_id.to_owned()
            }
            fn as_any(&self) -> Box<dyn Any> {
                Box::new(self.get_instance())
            }
        }

        impl Aead for $provider_name {
            fn new() -> Self
            where
                Self: Sized,
            {
                Self {
                    mode: $mode,
                    nonce_len: 12,
                }
            }
            fn get_instance(&self) -> Box<dyn Aead> {
                Box::new(Self {
                    mode: $mode,
                    nonce_len: 12,
                })
            }

            // Nonce and key generation helper.
            fn key_gen(&self) -> Vec<u8> {
                aead_key_gen(self.mode)
            }
            fn key_len(&self) -> usize {
                aead_key_size(self.mode)
            }
            fn nonce_gen(&self) -> Vec<u8> {
                aead_nonce_gen(self.mode).to_vec()
            }
            fn nonce_len(&self) -> usize {
                self.nonce_len
            }

            // Single-shot encryption/decryption.
            fn encrypt(
                &self,
                key: &[u8],
                nonce: &[u8],
                aad: &[u8],
                m: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let mut n = [0u8; 12];
                n.clone_from_slice(nonce);
                let (ctxt, tag) = evercrypt::aead::Aead::new(self.mode, key)
                    .unwrap()
                    .encrypt(m, &n, aad)
                    .unwrap();
                Ok((ctxt, tag.to_vec()))
            }

            fn decrypt(
                &self,
                key: &[u8],
                nonce: &[u8],
                aad: &[u8],
                c: &[u8],
                tag: &[u8],
            ) -> Result<Vec<u8>, String> {
                let ctxt = match evercrypt::aead::Aead::new(self.mode, key)
                    .unwrap()
                    .decrypt(c, tag, nonce, aad)
                {
                    Ok(c) => c,
                    Err(e) => return Err(format!("Error: {:?}", e)),
                };
                Ok(ctxt)
            }
        }
    };
}

implement_aead!(AesGcm128Provider, "AES-GCM-128", AeadMode::Aes128Gcm);
implement_aead!(AesGcm256Provider, "AES-GCM-256", AeadMode::Aes128Gcm);
implement_aead!(
    Chacha20Poly1305Provider,
    "Chacha20Poly1305",
    AeadMode::Chacha20Poly1305
);

impl EvercryptProvider {
    pub fn new() -> BaseProvider {
        let mut aead_map: HashMap<_, Box<dyn Aead>> = HashMap::new();
        aead_map.insert("AES-GCM-128".to_owned(), Box::new(AesGcm128Provider::new()));
        aead_map.insert("AES-GCM-256".to_owned(), Box::new(AesGcm256Provider::new()));
        aead_map.insert(
            "Chacha20Poly1305".to_owned(),
            Box::new(Chacha20Poly1305Provider::new()),
        );

        let digest_map: HashMap<_, Box<dyn Digest>> = HashMap::new();

        BaseProvider::new("EvercryptProvider", aead_map, digest_map)
    }
}

#[test]
pub fn provider_support() {
    let registry = Registry::new();
    registry.add(EvercryptProvider::new());
    let aes128gcm = registry.supports("AES-GCM-128");
    assert_eq!(true, aes128gcm);
}

#[test]
pub fn provider_algorithm() {
    let registry = Registry::new();
    registry.add(EvercryptProvider::new());
    let aes128gcm = registry
        .aead("AES-GCM-128")
        .expect("AES-GCM-128 should have been available");
    let key = aes128gcm.key_gen();
    let (ctxt, tag) = aes128gcm
        .encrypt(
            &key,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            &[],
            b"encrypted with aes gcm 128",
        )
        .unwrap();
    let msg = aes128gcm
        .decrypt(
            &key,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            &[],
            &ctxt,
            &tag,
        )
        .unwrap();
    assert_eq!(msg, b"encrypted with aes gcm 128");
}
