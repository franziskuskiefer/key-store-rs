//! # Key Store Types
//!
//! This module defines the [`Status`] enum.
//! The [`Status`] defines values to tag key store values with.

use std::convert::TryFrom;

use crate::{traits::KeyStoreValue, Error, KeyStoreResult};

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
            _ => {
                return Err(Error::InvalidStatus(format!(
                    "{} is not a valid status.",
                    value
                )))
            }
        })
    }
}

impl KeyStoreValue for Status {
    fn serialize(&self) -> KeyStoreResult<Vec<u8>> {
        Ok(vec![*self as u8])
    }

    fn deserialize(raw: &mut [u8]) -> KeyStoreResult<Self> {
        if raw.len() < 1 {
            return Err(Error::InvalidStatus(format!(
                "Can't deserialize an empty slice to a status."
            )));
        }
        Self::try_from(raw[0])
    }
}
