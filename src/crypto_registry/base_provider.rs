use std::collections::HashMap;

use super::traits::{Aead, Digest, Provider};

/// A basic implementation of a provider that can be used for convenience.
#[derive(Debug)]
pub struct BaseProvider {
    aead_map: HashMap<String, Box<dyn Aead>>,
    digest_map: HashMap<String, Box<dyn Digest>>,
}

impl BaseProvider {
    /// Create a new Provider with the given AEADs.
    pub fn new(
        aead_map: HashMap<String, Box<dyn Aead>>,
        digest_map: HashMap<String, Box<dyn Digest>>,
    ) -> BaseProvider {
        Self {
            aead_map,
            digest_map,
        }
    }
}

impl Provider for BaseProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        if self.aead(&algorithm).is_some() {
            return true;
        }
        if self.digest(&algorithm).is_some() {
            return true;
        }
        false
    }
    fn aead(&self, algorithm: &'static str) -> Option<&Box<dyn Aead>> {
        self.aead_map.get(&algorithm.to_string())
    }
    fn digest(&self, algorithm: &'static str) -> Option<&Box<dyn Digest>> {
        self.digest_map.get(&algorithm.to_string())
    }
}
