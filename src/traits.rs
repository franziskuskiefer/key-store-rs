//! # A Key Store Trait
//!
//! This module defines the [`KeyStore`] trait as well as a [`KeyStoreValue`] trait.
//! The key store defines a simple CRUD API with IDs of type [`KeyStore::KeyStoreId`]
//! and stores values that implement the (de)serialization define by the
//! [`KeyStoreValue`] trait.

use crate::types::Status;

/// The Key Store trait
pub trait KeyStore: Send + Sync {
    /// The type of the identifier used by the key store to identify values in
    /// the key store.
    type KeyStoreId;

    /// The error type returned by the [`KeyStore`].
    type Error;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization with [`Status`] `s` under ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store_with_status(
        &self,
        k: &Self::KeyStoreId,
        v: &impl KeyStoreValue,
        s: Status,
    ) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Store a value `v` that implements the [`KeyStoreValue`] trait for
    /// serialization for ID `k`.
    /// The status will always be [`Status::Extractable`].
    /// To set the status of the value `v` use
    /// [`store_with_status`](`KeyStore::store_with_status`).
    ///
    /// Returns an error if storing fails.
    fn store(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Read and return a value stored for ID `k` that implements the
    /// [`KeyStoreValue`] trait for deserialization.
    /// If the value is marked as `Status::Hidden`, an error will be returned.
    ///
    /// Returns an error if storing fails.
    fn read<V: KeyStoreValue>(&self, k: &Self::KeyStoreId) -> Result<V, Self::Error>
    where
        Self: Sized;

    /// Update a value stored for ID `k` with a new value `v` that implements the
    /// [`KeyStoreValue`] trait for serialization.
    ///
    /// Returns an error if storing fails.
    fn update(&self, k: &Self::KeyStoreId, v: &impl KeyStoreValue) -> Result<(), Self::Error>
    where
        Self: Sized;

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete(&self, k: &Self::KeyStoreId) -> Result<(), Self::Error>
    where
        Self: Sized;
}

/// Any value that is stored in the key store must implement this trait.
/// In most cases these are the raw bytes of the object.
pub trait KeyStoreValue {
    /// The error type returned by the [`KeyStoreValue`].
    type Error;

    /// The type of a serialized key store value.
    type SerializedValue;

    /// Serialize the value and return it as byte vector.
    ///
    /// Returns an [`Error`](`KeyStoreValue::Error`) if the serialization fails.
    fn serialize(&self) -> Result<Self::SerializedValue, Self::Error>;

    /// Deserialize the byte slice and return the object.
    ///
    /// Returns an [`Error`](`KeyStoreValue::Error`) if the deserialization fails.
    fn deserialize(raw: &mut [u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
