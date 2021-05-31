use std::collections::HashMap;

use super::traits::{Aead,  Digest, Provider};

/// A basic implementation of a provider that can be used for convenience.
#[derive(Debug)]
pub struct BaseProvider {
    aead_map: HashMap<String, Box<dyn Aead>>,
    digest_map: HashMap<String, Box<dyn Digest>>,
    name: String,
}

impl BaseProvider {
    /// Create a new Provider with the given AEADs and digests.
    pub fn new(
        name: &str,
        aead_map: HashMap<String, Box<dyn Aead>>,
        digest_map: HashMap<String, Box<dyn Digest>>,
    ) -> BaseProvider {
        Self {
            aead_map,
            digest_map,
            name: name.into(),
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
    fn name(&self) -> &str {
        &self.name
    }
    fn aead(&self, algorithm: &'static str) -> Option<Box<dyn Aead>> {
        self.aead_map
            .get(&algorithm.to_string())
            .map(|alg| alg.get_instance())
    }
    fn digest(&self, algorithm: &'static str) -> Option<Box<dyn Digest>> {
        self.digest_map
            .get(&algorithm.to_string())
            .map(|alg| alg.get_instance())
    }
}
