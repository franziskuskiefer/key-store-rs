#[cfg(feature = "sqlite-backend")]
mod tests {
    use std::convert::TryInto;

    use digest::Digest;
    use sha2::Sha256;

    use key_store::{
        secret::Secret,
        sqlite_key_store::{KeyStore, PrivateKey},
        traits::*,
        types::*,
        Error, KeyStoreIdentifier, Result,
    };

    #[derive(Debug, PartialEq, Eq)]
    struct KeyId {
        id: Vec<u8>,
    }

    impl KeyStoreId for KeyId {
        fn id(&self) -> Result<KeyStoreIdentifier> {
            Ok(KeyStoreIdentifier(
                Sha256::digest(&self.id).try_into().unwrap(),
            ))
        }
    }

    #[test]
    fn basic() {
        // let _ = pretty_env_logger::try_init();
        // let ks = KeyStore::new(Path::new("test-db.sqlite"));
        // let ks = KeyStore::open(Path::new("test-db.sqlite"));
        let ks = KeyStore::default();
        let secret = Secret::try_from(vec![3u8; 32], SymmetricKeyType::Aes256, &[]).unwrap();
        let id = KeyId {
            id: b"Key Id 1".to_vec(),
        };

        ks.store(&id, &secret).unwrap();
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        let secret2 = Secret::try_from(vec![4u8; 32], SymmetricKeyType::Aes256, &[]).unwrap();
        let id2 = KeyId {
            id: b"Key Id 2".to_vec(),
        };

        ks.store(&id2, &secret2).unwrap();
        let secret_again = ks.read(&id2).unwrap();
        assert_eq!(secret2, secret_again);
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.delete(&id2).unwrap();
        let secret_again: Result<Secret> = ks.read(&id2);
        assert_eq!(Error::ReadError, secret_again.err().unwrap());

        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.update(&id, &secret2).unwrap();
        let secret_again = ks.read(&id).unwrap();
        assert_eq!(secret2, secret_again);

        // Generate KEM key pair and use it in HPKE.
        let (pk, sk_id) = ks
            .new_key_pair(
                AsymmetricKeyType::KemKey(KemKeyType::X25519),
                Status::Hidden,
                b"hidden x25519 key pair",
            )
            .expect("Error generating x25519 key pair");
        let err: Result<PrivateKey> = ks.read(&sk_id);
        assert_eq!(err.err(), Some(Error::ForbiddenExtraction));

        let (ct, enc) = ks
            .hpke_seal_to_pk(
                HpkeKdfType::HkdfSha256,
                AeadType::Aes128Gcm,
                &pk,
                b"info string",
                b"test aad",
                b"HPKE test payload",
            )
            .expect("Error sealing to PK");

        let msg = ks
            .hpke_open_with_sk(
                HpkeKdfType::HkdfSha256,
                AeadType::Aes128Gcm,
                &sk_id,
                &ct,
                &enc,
                b"info string",
                b"test aad",
            )
            .expect("Error opening HPKE.");
        assert_eq!(msg.as_slice(), b"HPKE test payload");
    }
}
