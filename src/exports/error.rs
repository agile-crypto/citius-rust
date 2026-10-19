use std::fmt::Debug;

use crate::bindings::*;

#[derive(Debug)]
// #[derive(Display)]
pub enum Error {
    InvalidArgument(&'static str),
    AbiMismatch,
    NoMatchingTemplate,
    AlreadyExists,
    KeyNotFound,
    BufferTooSmall{needed: usize}
}

impl Error {
    pub fn rc(&self) -> agc_rc {
        match self {
            Self::InvalidArgument(_) => AGC_ERR_INVALID_ARGUMENT,
            Self::AbiMismatch => AGC_ERR_ABI_MISMATCH,
            Self::NoMatchingTemplate => AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE,
            Self::AlreadyExists => AGC_ERR_ALREADY_EXISTS,
            Self::KeyNotFound => AGC_ERR_CRYPTO_KEY_NOT_FOUND,
            Self::BufferTooSmall{..}=> AGC_ERR_BUFFER_TOO_SMALL
        }
    }
}
//  impl std::error::Error for Error {}