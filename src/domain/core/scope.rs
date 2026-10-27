/// The kind of intent a key serves: the primitive family whose scopes it can
/// be used for. Every key is created for exactly one kind, and every template
/// serves one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeKind {
    Signature,
    Aead,
    Mac,
    Kem,
    KeyAgreement,
    Kdf,
    Hash,
    KeyWrapping,
    SymmetricCipher,
    GenericSecret,
    DiskEncryption,
    AsymmetricEncryption,
}
