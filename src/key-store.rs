use std::{path::Path, result};

use rusqlite::{params, types::ToSqlOutput, Connection, OpenFlags, ToSql};
use traits::{KeyStoreId, KeyStoreTrait, KeyStoreValue};

#[cfg(feature = "openmls_keys")]
pub mod openmls;
#[cfg(feature = "secret")]
pub mod secret;
pub mod traits;

pub struct KeyStoreIdentifier([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    WriteError,
    ReadError,
    UpdateError,
    DeleteError,
}

type Result<T> = result::Result<T, Error>;

pub struct KeyStore {
    sql: Connection,
}

fn init_key_store(connection: &Connection) -> Result<()> {
    connection
        .execute(
            "CREATE TABLE secrets (
              id              INTEGER PRIMARY KEY,
              label           BLOB,
              value           BLOB,
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
        Self { sql: connection }
    }
}

impl KeyStore {
    pub fn new(path: &Path) -> Self {
        let connection = Connection::open(path).unwrap();
        init_key_store(&connection).unwrap();
        Self { sql: connection }
    }

    pub fn open(path: &Path) -> Self {
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        Self { sql: connection }
    }
}

impl ToSql for KeyStoreIdentifier {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_vec()))
    }
}

impl KeyStoreTrait for KeyStore {
    fn store(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()> {
        self.sql
            .execute(
                "INSERT INTO secrets (label, value) VALUES (?1, ?2)",
                params![k.id(), v.serialize()],
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::WriteError
            })?;
        Ok(())
    }

    fn read<V: KeyStoreValue>(&self, k: &impl KeyStoreId) -> Result<V> {
        let result: Vec<u8> = self
            .sql
            .query_row(
                "SELECT value FROM secrets WHERE label = ?1",
                params![k.id()],
                |row| Ok(row.get(0)?),
            )
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::ReadError
            })?;
        Ok(V::deserialize(&result))
    }

    fn update(&self, k: &impl KeyStoreId, v: &impl KeyStoreValue) -> Result<()> {
        let updated_rows = self
            .sql
            .execute(
                "UPDATE secrets SET value = ?1 WHERE label = ?2",
                params![v.serialize(), k.id()],
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

    fn delete(&self, k: &impl KeyStoreId) -> Result<()> {
        self.sql
            .execute("DELETE FROM secrets WHERE label = ?1", params![k.id()])
            .map_err(|e| {
                log::error!("SQL ERROR: {:?}", e);
                Error::DeleteError
            })?;
        Ok(())
    }
}

// === Unit Tests === //

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use evercrypt::digest::sha256;

    #[cfg(feature = "openmls_keys")]
    use crate::traits::OpenMlsKeyGenerator;
    use crate::{secret::Secret, traits::KeyStoreTrait};

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct KeyId {
        id: Vec<u8>,
    }

    impl KeyStoreId for KeyId {
        fn id(&self) -> KeyStoreIdentifier {
            KeyStoreIdentifier(sha256(&self.id).try_into().unwrap())
        }
    }

    #[test]
    fn basic() {
        // let ks = KeyStore::new(Path::new("test-db.sqlite"));
        // let ks = KeyStore::open(Path::new("test-db.sqlite"));
        let ks = KeyStore::default();
        let secret = Secret::from(vec![3u8; 32]);
        let id = KeyId {
            id: b"Key Id 1".to_vec(),
        };

        ks.store(&id, &secret).unwrap();
        let secret_again: Secret = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        let secret2 = Secret::from(vec![4u8; 32]);
        let id2 = KeyId {
            id: b"Key Id 2".to_vec(),
        };

        ks.store(&id2, &secret2).unwrap();
        let secret_again: Secret = ks.read(&id2).unwrap();
        assert_eq!(secret2, secret_again);
        let secret_again: Secret = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.delete(&id2).unwrap();
        let secret_again: Result<Secret> = ks.read(&id2);
        assert_eq!(Err(Error::ReadError), secret_again);

        let secret_again: Secret = ks.read(&id).unwrap();
        assert_eq!(secret, secret_again);

        ks.update(&id, &secret2).unwrap();
        let secret_again: Secret = ks.read(&id).unwrap();
        assert_eq!(secret2, secret_again);

        #[cfg(feature = "openmls_keys")]
        fn openmls_keys(ks: &KeyStore) {
            let id3 = KeyId {
                id: b"New Key Id".to_vec(),
            };
            ks.new_secret(&id3, 32).unwrap();
            let secret_again: Secret = ks.read(&id3).unwrap();
            println!("{:x?}", secret_again);
        }

        #[cfg(not(feature = "openmls_keys"))]
        fn openmls_keys(_: &KeyStore) {}

        openmls_keys(&ks);
    }
}
