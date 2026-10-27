//! A deterministic provider for tests (Go: the loopback provider): it serves
//! the templates it is given and "generates" recognisable, predictable bytes.

use std::sync::atomic::{AtomicU32, Ordering};

use zeroize::Zeroizing;

use super::{Backend, Capability, Channels, Encoding, GeneratedKey, Transfer};
use crate::domain::core::Error;
use crate::proto::api;

pub struct FakeProvider {
    name: &'static str,
    templates: Vec<&'static str>,
    implementation: api::ImplementationProperties,
    transfer: Transfer,
    generated: AtomicU32,
}

impl FakeProvider {
    pub fn new(name: &'static str, templates: &[&'static str]) -> Self {
        FakeProvider {
            name,
            templates: templates.to_vec(),
            implementation: api::ImplementationProperties::default(),
            // Like a stateless software provider: its (raw) material is the
            // payload the core stores.
            transfer: Transfer {
                emit: Channels { stored_payload: vec![Encoding::Raw], ..Default::default() },
                accept: Channels { stored_payload: vec![Encoding::Raw], ..Default::default() },
            },
            generated: AtomicU32::new(0),
        }
    }

    pub fn with(mut self, f: impl FnOnce(&mut api::ImplementationProperties)) -> Self {
        f(&mut self.implementation);
        self
    }

    pub fn with_transfer(mut self, t: Transfer) -> Self {
        self.transfer = t;
        self
    }
}

impl Backend for FakeProvider {
    fn name(&self) -> &str {
        self.name
    }

    fn kind(&self) -> &str {
        "fake"
    }

    fn supported_templates(&self) -> &[&'static str] {
        &self.templates
    }

    fn capabilities(&self) -> &[Capability] {
        &[
            Capability::Sign,
            Capability::Cipher,
            Capability::Mac,
            Capability::Hash,
            Capability::Random,
            Capability::KeyEstablishment,
        ]
    }

    fn implementation(&self) -> api::ImplementationProperties {
        self.implementation.clone()
    }

    fn transfer(&self, _algorithm: &api::AlgorithmDetails) -> Transfer {
        self.transfer.clone()
    }

    fn generate_key(&self, _algorithm: &api::AlgorithmDetails) -> Result<GeneratedKey, Error> {
        let n = self.generated.fetch_add(1, Ordering::Relaxed);
        Ok(GeneratedKey {
            private: Zeroizing::new(format!("{}-{n}", self.name).into_bytes()),
            private_encoding: Encoding::Raw,
            public: None,
        })
    }
}
