#![allow(non_upper_case_globals)]

use std::{fmt::Display, ffi::CStr, ptr};

use mongocrypt_sys::{mongocrypt_status_destroy, mongocrypt_status_new, mongocrypt_status_t, mongocrypt_status_type, mongocrypt_status_type_t_MONGOCRYPT_STATUS_OK, mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT, mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS, mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE, mongocrypt_status_code, mongocrypt_status_message};

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub code: u32,
    pub message: Option<String>,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({})", self.kind, self.code)?;
        if let Some(s) = &self.message {
            write!(f, ": {}", s)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Client,
    Kms,
    CsFle,
    Internal,
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Status {
    inner: *mut mongocrypt_status_t,
}

impl Status {
    pub(crate) fn new() -> Self {
        Self { inner: unsafe { mongocrypt_status_new() } }
    }

    pub(crate) fn native(inner: *mut mongocrypt_status_t) -> Self {
        Self { inner }
    }

    pub(crate) fn check(&self) -> Result<()> {
        let typ = unsafe { mongocrypt_status_type(self.inner) };
        let kind = match typ {
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_OK => return Ok(()),
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT => ErrorKind::Client,
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS => ErrorKind::Kms,
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE => ErrorKind::CsFle,
            _ => ErrorKind::Internal,
        };
        if kind == ErrorKind::Internal {
            return Err(Error { kind, code: 0, message: Some(format!("unhandled status type {}", typ)) });
        }
        let code = unsafe { mongocrypt_status_code(self.inner) };
        let message_ptr = unsafe { mongocrypt_status_message(self.inner, ptr::null_mut()) };
        let message = if message_ptr == ptr::null_mut() {
            None
        } else {
            let c_message = unsafe { CStr::from_ptr(message_ptr) };
            let message = c_message
                .to_str()
                .map_err(|err| {
                    Error { kind: ErrorKind::Internal, code: 0, message: Some(format!("invalid status message: {}", err)) }
                })?;
            Some(message.to_string())
        };
        Err(Error { kind, code, message })
    }
}

impl Drop for Status {
    fn drop(&mut self) {
        unsafe { mongocrypt_status_destroy(self.inner); }
    }
}