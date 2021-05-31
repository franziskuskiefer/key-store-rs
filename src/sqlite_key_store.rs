use std::{
    convert::{TryFrom, TryInto},
    path::Path,
    sync::Mutex,
};

use crate::{
    keys::{AsymmetricKeyError, PublicKey},
    secret::Secret,
    traits::{
        GenerateKeys, Hash, Hasher, HkdfDerive, HpkeDerive, HpkeOpen, HpkeSeal, KeyStoreId,
        KeyStoreTrait, KeyStoreValue, Open, Seal, Sign, Supports, Verify,
    },
    types::{
        AeadType, AsymmetricKeyType, Ciphertext, HashType, HpkeKdfType, HpkeKemType, KemKeyType,
        KemOutput, Plaintext, PrivateKeyId, Signature, SignatureKeyType, Status, SymmetricKeyType,
    },
    Error, KeyStoreIdentifier, Result,
};
use evercrypt::{
    aead, digest as evercrypt_digest, ed25519, hkdf, hmac, p256,
    prelude::{p256_ecdsa_random_nonce, DigestMode},
    signature, x25519,
};
use hpke::{self, prelude::*, Hpke};
use rusqlite::{
    params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OpenFlags, ToSql,
};

mod types;
pub use types::PrivateKey;

pub struct KeyStore {
    sql: Mutex<Connection>,
}

fn init_key_store(connection: &Connection) -> Result<()> {
    connection
        .execute(
            "CREATE TABLE secrets (
              id              INTEGER PRIMARY KEY,
              label           BLOB,
              value           BLOB,
              status          INTEGER,
              UNIQUE(label)
              )",
            [],
        )
        .map_err(|e| {
            log::error!("SQL ERROR: {:?}", e);
            Error::WriteError
        })?;
    Ok(())
}

impl Default for KeyStore {
    fn default() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        init_key_store(&connection).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }
}

/// Public proprietary API.
impl KeyStore {
    pub fn new(path: &Path) -> Self {
        let connection = Connection::open(path).unwrap();
        init_key_store(&connection).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }

    pub fn open(path: &Path) -> Self {
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        Self {
            sql: Mutex::new(connection),
        }
    }
}

impl ToSql for KeyStoreIdentifier {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_vec()))
    }
}

impl FromSql for Status {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let raw = u8::column_result(value)?;
        Self::try_from(raw).map_err(|_| FromSqlError::OutOfRange(raw.into()))
    }
}

/// Private functions.
impl KeyStore {
    fn _store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue, status: Status) -> Result<()> {
        let connection = self.sql.lock()?;
        connection
            .execute(
                "INSERT INTO secrets (label, value, status) VALUES (?1, ?2, ?3)",
                params![k.id()?, v.serialize()?, status as u8],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::WriteError
            })?;
        Ok(())
    }

    fn internal_read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<(V, Status)> {
        let connection = self.sql.lock()?;
        let mut result: (Vec<u8>, Status) = connection
            .query_row(
                "SELECT value, status FROM secrets WHERE label = ?1",
                params![k.id()?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::ReadError
            })?;
        Ok((V::deserialize(&mut result.0)?, result.1))
    }

    fn _read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V> {
        let (v, status) = self.internal_read(k)?;
        match status {
            Status::Extractable | Status::UnconfirmedExtractable => Ok(v),
            Status::Hidden | Status::UnconfirmedHidden => Err(Error::ForbiddenExtraction),
        }
    }

    fn _update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()> {
        let connection = self.sql.lock()?;
        let updated_rows = connection
            .execute(
                "UPDATE secrets SET value = ?1 WHERE label = ?2",
                params![v.serialize()?, k.id()?],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::UpdateError
            })?;
        if updated_rows == 1 {
            Ok(())
        } else {
            Err(Error::UpdateError)
        }
    }

    fn _delete(&self, k: &impl KeyStoreId) -> Result<()> {
        let connection = self.sql.lock()?;
        connection
            .execute("DELETE FROM secrets WHERE label = ?1", params![k.id()?])
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::DeleteError
            })?;
        Ok(())
    }
}

impl KeyStoreTrait for KeyStore {
    fn store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()> {
        self._store(k, v, Status::Extractable)
    }

    fn read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V> {
        self._read(k)
    }

    fn update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()> {
        self._update(k, v)
    }

    fn delete(&self, k: &impl KeyStoreId) -> Result<()> {
        self._delete(k)
    }
}

impl Supports for KeyStore {
    fn symmetric_key_types(&self) -> Vec<SymmetricKeyType> {
        vec![
            SymmetricKeyType::Aes128,
            SymmetricKeyType::Aes256,
            SymmetricKeyType::ChaCha20,
        ]
    }

    fn asymmetric_key_types(&self) -> Vec<AsymmetricKeyType> {
        vec![
            AsymmetricKeyType::KemKey(KemKeyType::X25519),
            AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519),
            AsymmetricKeyType::KemKey(KemKeyType::P256),
            AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256),
        ]
    }
}

#[inline]
fn hash_type_to_evercrypt(hash: HashType) -> Result<DigestMode> {
    Ok(match hash {
        HashType::Sha1 => DigestMode::Sha1,
        HashType::Sha2_224 => DigestMode::Sha224,
        HashType::Sha2_256 => DigestMode::Sha256,
        HashType::Sha2_384 => DigestMode::Sha256,
        HashType::Sha2_512 => DigestMode::Sha512,
        HashType::Sha3_224 => DigestMode::Sha3_224,
        HashType::Sha3_256 => DigestMode::Sha3_256,
        HashType::Sha3_384 => DigestMode::Sha3_384,
        HashType::Sha3_512 => DigestMode::Sha3_512,
    })
}

impl From<evercrypt::digest::Error> for Error {
    fn from(e: evercrypt::digest::Error) -> Self {
        Self::DigestError(format!("Evercrypt digest error: {:?}", e))
    }
}

impl Hash for KeyStore {
    type StatefulHasher = evercrypt::digest::Digest;

    fn hash(&self, hash: HashType, data: &[u8]) -> Result<Vec<u8>> {
        Ok(evercrypt::digest::hash(hash_type_to_evercrypt(hash)?, data))
    }

    fn hasher(&self, hash: HashType) -> Result<Self::StatefulHasher> {
        evercrypt::digest::Digest::new(hash_type_to_evercrypt(hash)?).map_err(|e| e.into())
    }
}

impl Hasher for evercrypt::digest::Digest {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        self.update(data).map_err(|e| e.into())
    }

    fn finish(&mut self) -> Result<Vec<u8>> {
        self.finish().map_err(|e| e.into())
    }
}

impl GenerateKeys for KeyStore {
    fn new_secret(
        &self,
        key_type: SymmetricKeyType,
        status: Status,
        k: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<()> {
        if !self.symmetric_key_types().contains(&key_type) {
            return Err(Error::UnsupportedSecretType(key_type));
        }
        let mut randomness = rand::thread_rng();
        let secret = Secret::random_bor(&mut randomness, key_type, label);
        self._store(k, &secret, status)
    }

    fn new_key_pair(
        &self,
        key_type: AsymmetricKeyType,
        status: Status,
        label: &[u8],
    ) -> Result<(PublicKey, PrivateKeyId)> {
        let (public_key, private_key) = match key_type {
            AsymmetricKeyType::KemKey(KemKeyType::X25519) => {
                let private_key = x25519::key_gen();
                let public_key = x25519::dh_base(&private_key);
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519) => {
                let private_key = ed25519::key_gen();
                let public_key = ed25519::sk2pk(&private_key);
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256)
            | AsymmetricKeyType::KemKey(KemKeyType::P256) => {
                let private_key = p256::key_gen().map_err(|e| {
                    Error::CryptoLibError(format!("P256 key generation error: {:?}", e))
                })?;
                let public_key = p256::dh_base(&private_key)
                    .map_err(|e| AsymmetricKeyError::CryptoLibError(format!("{:?}", e)))?;
                let public_key = PublicKey::from(key_type, &public_key, label);
                let private_key = PrivateKey::from(key_type, &private_key, label, &public_key);
                (public_key, private_key)
            }
            _ => return Err(Error::UnsupportedKeyType(key_type)),
        };
        let mut sha256 = self.hasher(HashType::Sha2_256)?;
        sha256.update(label)?;
        sha256.update(public_key.as_slice())?;
        let id = sha256.finish()?;
        self._store(&id, &private_key, status)?;
        Ok((public_key, id))
    }
}

fn hmac_type(hash: HashType) -> Result<hmac::Mode> {
    match hash {
        HashType::Sha1 => Ok(hmac::Mode::Sha1),
        HashType::Sha2_256 => Ok(hmac::Mode::Sha256),
        HashType::Sha2_384 => Ok(hmac::Mode::Sha384),
        HashType::Sha2_512 => Ok(hmac::Mode::Sha512),
        _ => Err(Error::UnsupportedAlgorithm(format!("{:?}", hash))),
    }
}

impl KeyStore {
    fn extract_unsafe(&self, hash: HashType, ikm: &impl KeyStoreId, salt: &[u8]) -> Result<Secret> {
        let mode = hmac_type(hash)?;
        let (ikm_secret, _status): (Secret, Status) = self.internal_read(ikm)?;
        let prk = hkdf::extract(mode, salt, ikm_secret.as_slice());
        let prk_len = prk.len();
        Secret::try_from(
            prk,
            SymmetricKeyType::Any(prk_len.try_into().map_err(|_| {
                Error::InvalidLength(format!(
                    "HKDF PRK is too long ({}) for a secret (u16)",
                    prk_len
                ))
            })?),
            b"HKDF-PRK",
        )
    }

    fn expand_unsafe(
        &self,
        hash: HashType,
        prk: Secret,
        info: &[u8],
        out_len: usize,
    ) -> Result<Secret> {
        let mode = hmac_type(hash)?;
        let key = hkdf::expand(mode, prk.as_slice(), info, out_len);
        if key.is_empty() {
            return Err(Error::InvalidLength(format!(
                "Invalid HKDF output length {}",
                out_len
            )));
        }
        let key_len = key.len();
        Secret::try_from(
            key,
            SymmetricKeyType::Any(key_len.try_into().map_err(|_| {
                Error::InvalidLength(format!(
                    "HKDF key is too long ({}) for a secret (u16)",
                    key_len
                ))
            })?),
            b"HKDF-KEY",
        )
    }
}

impl HkdfDerive for KeyStore {
    fn hkdf(
        &self,
        hash: HashType,
        ikm: &impl KeyStoreId,
        salt: &[u8],
        info: &[u8],
        out_len: usize,
        okm: &impl KeyStoreId,
    ) -> Result<()> {
        let prk = self.extract_unsafe(hash, ikm, salt)?;
        let key = self.expand_unsafe(hash, prk, info, out_len)?;
        self.store(okm, &key)
    }
}

fn aead_type(aead: AeadType) -> Result<aead::Mode> {
    match aead {
        AeadType::Aes128Gcm => Ok(aead::Mode::Aes128Gcm),
        AeadType::Aes256Gcm => Ok(aead::Mode::Aes256Gcm),
        AeadType::ChaCha20Poly1305 => Ok(aead::Mode::Chacha20Poly1305),
        AeadType::Export => Err(Error::UnsupportedAlgorithm(format!("HPKE Export AEAD"))),
    }
}

impl Seal for KeyStore {
    fn seal(
        &self,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        msg: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Ciphertext> {
        let (key, _status): (Secret, Status) = self.internal_read(key_id)?;
        let mode = aead_type(aead)?;
        let (ct, tag) = aead::encrypt(mode, key.as_slice(), msg, nonce, aad)
            .map_err(|e| Error::EncryptionError(format!("Error encrypting: {:?}", e)))?;
        Ok(Ciphertext::new(ct, tag))
    }
}

impl Open for KeyStore {
    fn open(
        &self,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        cipher_text: &Ciphertext,
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Plaintext> {
        let (key, _status): (Secret, Status) = self.internal_read(key_id)?;
        let mode = aead_type(aead)?;
        let pt = aead::decrypt(
            mode,
            key.as_slice(),
            cipher_text.cipher_text(),
            cipher_text.tag(),
            nonce,
            aad,
        )
        .map_err(|e| Error::DecryptionError(format!("Decryption encrypting: {:?}", e)))?;
        Ok(Plaintext::new(pt))
    }
}

fn evercrypt_kem_type(key_type: AsymmetricKeyType) -> Result<HpkeKemMode> {
    match key_type {
        AsymmetricKeyType::KemKey(KemKeyType::P256) => Ok(HpkeKemMode::DhKemP256),
        AsymmetricKeyType::KemKey(KemKeyType::P384) => Ok(HpkeKemMode::DhKemP384),
        AsymmetricKeyType::KemKey(KemKeyType::P521) => Ok(HpkeKemMode::DhKemP521),
        AsymmetricKeyType::KemKey(KemKeyType::X25519) => Ok(HpkeKemMode::DhKem25519),
        AsymmetricKeyType::KemKey(KemKeyType::X448) => Ok(HpkeKemMode::DhKem448),
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", key_type))),
    }
}

impl HpkeSeal for KeyStore {
    fn seal(
        &self,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, KemOutput)> {
        let (pk_r, _status): (PublicKey, Status) = self.internal_read(key_id)?;
        self.seal_to_pk(kdf, aead, &pk_r, info, aad, payload)
    }

    fn seal_to_pk(
        &self,
        kdf: HpkeKdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, KemOutput)> {
        let kem = evercrypt_kem_type(key.key_type())?;
        let hpke = Hpke::new(
            hpke::Mode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let (kem_output, ciphertext) = hpke
            .seal(&key.as_slice().into(), info, aad, payload, None, None, None)
            .map_err(|e| Error::CryptoLibError(format!("HPKE Seal error: {:?}", e)))?;
        Ok((ciphertext, KemOutput::new(kem_output)))
    }

    fn seal_secret(
        &self,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Vec<u8>, KemOutput)> {
        let (pk_r, _status): (PublicKey, Status) = self.internal_read(key_id)?;
        self.seal_secret_to_pk(kdf, aead, &pk_r, info, aad, secret_id)
    }

    fn seal_secret_to_pk(
        &self,
        kdf: HpkeKdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &impl KeyStoreId,
    ) -> Result<(Vec<u8>, KemOutput)> {
        let kem = evercrypt_kem_type(key.key_type())?;
        let (secret, _status): (Secret, Status) = self.internal_read(secret_id)?;
        let hpke = Hpke::new(
            hpke::Mode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let (kem_output, ciphertext) = hpke
            .seal(
                &key.as_slice().into(),
                info,
                aad,
                secret.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|e| Error::CryptoLibError(format!("HPKE Seal error: {:?}", e)))?;
        Ok((ciphertext, KemOutput::new(kem_output)))
    }
}

impl HpkeOpen for KeyStore {
    fn open_with_sk(
        &self,
        kdf: HpkeKdfType,
        aead: AeadType,
        key_id: &impl KeyStoreId,
        cipher_text: &[u8],
        kem_out: &KemOutput,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Plaintext> {
        let (sk_r, _status): (PrivateKey, Status) = self.internal_read(key_id)?;
        let kem = evercrypt_kem_type(sk_r.key_type())?;
        let hpke = Hpke::new(
            hpke::Mode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let ptxt = hpke
            .open(
                kem_out.as_slice(),
                &sk_r.as_slice().into(),
                info,
                aad,
                cipher_text,
                None,
                None,
                None,
            )
            .map_err(|e| Error::CryptoLibError(format!("HPKE Open error: {:?}", e)))?;
        Ok(Plaintext::new(ptxt))
    }
}

impl HpkeDerive for KeyStore {
    fn derive_key_pair(
        &self,
        kem: HpkeKemType,
        kdf: HpkeKdfType,
        aead: AeadType,
        ikm_id: &impl KeyStoreId,
        private_key_id: &impl KeyStoreId,
        label: &[u8],
    ) -> Result<PublicKey> {
        let (ikm, _status): (Secret, Status) = self.internal_read(ikm_id)?;
        let hpke = Hpke::new(
            hpke::Mode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let key_pair = hpke
            .derive_key_pair(ikm.as_slice())
            .map_err(|e| Error::CryptoLibError(format!("HPKE Derive key pair error: {:?}", e)))?;
        let (private_key, public_key) = key_pair.into_keys();
        let key_type = AsymmetricKeyType::try_from(kem)?;
        let public_key = PublicKey::from(key_type, public_key.as_slice(), label);
        let private_key = PrivateKey::from(key_type, private_key.as_slice(), label, &public_key);
        self.store(private_key_id, &private_key)?;
        Ok(public_key)
    }
}

fn evercrypt_signature_type(key_type: AsymmetricKeyType) -> Result<signature::Mode> {
    match key_type {
        AsymmetricKeyType::SignatureKey(SignatureKeyType::Ed25519) => Ok(signature::Mode::Ed25519),
        AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP256Sha256)
        | AsymmetricKeyType::SignatureKey(SignatureKeyType::EcdsaP521Sha512) => {
            Ok(signature::Mode::P256)
        }
        _ => return Err(Error::UnsupportedAlgorithm(format!("{:?}", key_type))),
    }
}

impl Sign for KeyStore {
    fn sign(
        &self,
        key_id: &impl KeyStoreId,
        payload: &[u8],
        hash: impl Into<Option<HashType>>,
    ) -> Result<Signature> {
        let (sk, _status): (PrivateKey, Status) = self.internal_read(key_id)?;
        let hash = hash.into();
        let evercrypt_hash = evercrypt_hash_type(hash);
        let signature_mode = evercrypt_signature_type(sk.key_type())?;
        let nonce = if signature_mode == signature::Mode::P256 {
            Some(p256_ecdsa_random_nonce().map_err(|e| {
                Error::CryptoLibError(format!("P256 nonce generation error: {:?}", e))
            })?)
        } else {
            None
        };
        let signature = signature::sign(
            signature_mode,
            evercrypt_hash,
            &sk.as_slice(),
            payload,
            nonce.as_ref(),
        )
        .map_err(|e| Error::CryptoLibError(format!("P256 nonce generation error: {:?}", e)))?;
        Ok(Signature::new(signature, hash))
    }
}

fn evercrypt_hash_type(
    hash: impl Into<Option<HashType>>,
) -> Option<evercrypt::prelude::DigestMode> {
    if let Some(hash) = hash.into() {
        Some(match hash {
            HashType::Sha1 => evercrypt_digest::Mode::Sha1,
            HashType::Sha2_224 => evercrypt_digest::Mode::Sha224,
            HashType::Sha2_256 => evercrypt_digest::Mode::Sha256,
            HashType::Sha2_384 => evercrypt_digest::Mode::Sha384,
            HashType::Sha2_512 => evercrypt_digest::Mode::Sha512,
            HashType::Sha3_224 => evercrypt_digest::Mode::Sha3_224,
            HashType::Sha3_256 => evercrypt_digest::Mode::Sha3_256,
            HashType::Sha3_384 => evercrypt_digest::Mode::Sha3_384,
            HashType::Sha3_512 => evercrypt_digest::Mode::Sha3_512,
        })
    } else {
        None
    }
}

impl Verify for KeyStore {
    fn verify(
        &self,
        key_id: &impl KeyStoreId,
        signature: &Signature,
        payload: &[u8],
    ) -> Result<()> {
        let (pk, _status): (PublicKey, Status) = self.internal_read(key_id)?;
        self.verify_with_pk(&pk, signature, payload)
    }

    fn verify_with_pk(&self, key: &PublicKey, signature: &Signature, payload: &[u8]) -> Result<()> {
        let mode = evercrypt_signature_type(key.key_type())?;
        let hash = evercrypt_hash_type(signature.hash_type());
        let valid = signature::verify(mode, hash, key.as_slice(), signature.as_slice(), payload)
            .map_err(|e| Error::InvalidSignature(format!("Error verifying signature: {:?}", e)))?;
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidSignature(format!("Invalid signature")))
        }
    }
}
