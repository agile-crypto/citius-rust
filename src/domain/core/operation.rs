/// An operation a crypto policy can allow or deny. The names are the strings
/// policy documents use (`allowed_operations.key_operations`), as in Go's
/// `core.Operation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    CreateKey,
    ReadKey,
    DeleteKey,
    Sign,
    Verify,
    DigestSign,
    DigestVerify,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    DeriveKey,
    RotateKey,
}

impl Operation {
    pub const ALL: [Operation; 13] = [
        Operation::CreateKey,
        Operation::ReadKey,
        Operation::DeleteKey,
        Operation::Sign,
        Operation::Verify,
        Operation::DigestSign,
        Operation::DigestVerify,
        Operation::Encrypt,
        Operation::Decrypt,
        Operation::Wrap,
        Operation::Unwrap,
        Operation::DeriveKey,
        Operation::RotateKey,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::CreateKey => "create_key",
            Operation::ReadKey => "read_key",
            Operation::DeleteKey => "delete_key",
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::DigestSign => "digest_sign",
            Operation::DigestVerify => "digest_verify",
            Operation::Encrypt => "encrypt",
            Operation::Decrypt => "decrypt",
            Operation::Wrap => "wrap",
            Operation::Unwrap => "unwrap",
            Operation::DeriveKey => "derive_key",
            Operation::RotateKey => "rotate_key",
        }
    }

    pub fn from_name(name: &str) -> Option<Operation> {
        Operation::ALL.into_iter().find(|o| o.as_str() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for op in Operation::ALL {
            assert_eq!(Operation::from_name(op.as_str()), Some(op));
        }
        assert_eq!(Operation::from_name("Sign"), None);
    }
}
