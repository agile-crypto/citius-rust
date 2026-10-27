use std::fmt;

/// What went wrong, independent of how a caller sees it. The FFI layer maps
/// each code to an `agc_rc` in one place (`ffi/error.rs`), the way the Go
/// server maps domain codes to gRPC statuses only in `ToStatusError`.
///
/// Finer than Go's codes where the C API distinguishes cases Go folds
/// together, e.g. `TemplateNotFound` (a lookup by id missed) versus
/// `NoMatchingTemplate` (selection found nothing eligible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidArgument,
    AlreadyExists,
    KeyNotFound,
    TemplateNotFound,
    TemplateDeprecated,
    TemplateForbidden,
    NoMatchingTemplate,
    PolicyNotFound,
    /// The policy denies the operation; also a policy still bound to keys.
    PolicyViolation,
    /// An invariant the library itself is responsible for was broken, e.g. a
    /// lock poisoned by an earlier panic.
    Internal,
}

/// The one error type of the domain and application layers, like
/// citius-core's `errors.Error`: a code, the operation that failed, and a
/// message for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: Code,
    op: &'static str,
    message: String,
}

impl Error {
    pub fn new(code: Code, op: &'static str, message: impl Into<String>) -> Self {
        Error {
            code,
            op,
            message: message.into(),
        }
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn op(&self) -> &'static str {
        self.op
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.op, self.message)
    }
}

impl std::error::Error for Error {}

/// A lock is poisoned only if a thread panicked while holding it. The panic
/// was caught at the C boundary, but the data behind the lock may be half
/// updated, so every later use fails closed instead of trusting it.
pub fn poisoned(op: &'static str) -> Error {
    Error::new(Code::Internal, op, "internal state is unusable after an earlier failure")
}
