//! # Key Store Types
//!
//! This module defines the [`Status`] enum.
//! The [`Status`] defines values to tag key store values with.
//!
//! XXX: We might want to make the [`Status`] a trait type as well 🤔.

use std::convert::TryFrom;

use crate::traits::KeyStoreValue;

/// Errors thrown by operations on the [`Status`].
pub enum StatusError {
    /// The value can't be converted to a [`Status`].
    InvalidStatus(String),

    /// Deserializing a byte slice failed.
    DeserializationError(String),
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
    type Error = StatusError;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Extractable,
            2 => Self::Hidden,
            3 => Self::UnconfirmedExtractable,
            4 => Self::UnconfirmedHidden,
            _ => {
                return Err(Self::Error::InvalidStatus(format!(
                    "{} is not a valid status.",
                    value
                )))
            }
        })
    }
}

impl KeyStoreValue for Status {
    type Error = StatusError;

    type SerializedValue = Vec<u8>;

    fn serialize(&self) -> Result<Self::SerializedValue, Self::Error> {
        Ok(vec![*self as u8])
    }

    fn deserialize(raw: &mut [u8]) -> Result<Self, Self::Error> {
        if raw.len() < 1 {
            return Err(Self::Error::DeserializationError(format!(
                "Can't deserialize an empty slice to a status."
            )));
        }
        Self::try_from(raw[0])
    }
}
