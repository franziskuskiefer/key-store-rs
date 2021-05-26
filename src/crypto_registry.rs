use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

use self::traits::{Aead, Digest, Provider};

pub mod base_provider;
pub mod traits;
pub mod algorithms;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
}

/// The `Registry` holding all providers.
#[derive(Debug)]
pub struct Registry {
    providers: Arc<Mutex<Vec<Box<dyn Provider>>>>,
}

macro_rules! get_algorithm {
    ( $( $name:ident => $ty:ty ; )* ) => {
        $(
            pub fn $name(&self, algorithm: &'static str) -> Result<Box<$ty>, &'static str> {
                let providers = self.providers.lock().unwrap();
                for provider in providers.iter() {
                    if let Some(c) = provider.$name(algorithm) {
                        return Ok(c.get_instance());
                    }
                }
                Err("Unsupported algorithm")
            }
        )*
    };
}

impl Registry {
    /// Initialise the `Registry`.
    fn new() -> Registry {
        Registry {
            providers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a new provider to the `Registry`.
    pub fn add<T: Provider + 'static>(&self, provider: T) {
        let mut providers = self.providers.lock().unwrap();
        providers.push(Box::new(provider));
    }

    /// Remove all providers from the `Registry`.
    pub fn clear(&self) {
        let mut providers = self.providers.lock().unwrap();
        providers.clear();
    }

    /// Check support for an `algorithm`.
    /// Returns `true` if a `Provider` is registered that supports the `algorithm`.
    pub fn supports(&self, algorithm: &'static str) -> bool {
        let providers = self.providers.lock().unwrap();
        for provider in providers.iter() {
            if provider.supports(&algorithm) {
                return true;
            }
        }
        false
    }

    // Define convenience functions to get an algorithm implementation.
    get_algorithm! {
        aead => dyn Aead;
        digest => dyn Digest;
    }
}
