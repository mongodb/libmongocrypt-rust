use std::{fmt::{Display, Debug}, ffi::CStr, ptr};

use mongocrypt_sys as sys;

#[derive(Debug)]
pub struct Error<K> {
    pub kind: K,
    pub code: u32,
    pub message: Option<String>,
}

impl<K: Debug> Display for Error<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({})", self.kind, self.code)?;
        if let Some(s) = &self.message {
            write!(f, ": {}", s)?;
        }
        Ok(())
    }
}

impl<K: Debug> std::error::Error for Error<K> {
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    // These correspond to errors from libmongocrypt
    Crypt(ErrorKindCrypt),
    // These are produced in this crate
    Encoding,
    Overflow,
    Internal,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKindCrypt {
    Client,
    Kms,
    CsFle,
}

impl From<Error<ErrorKindCrypt>> for Error<ErrorKind> {
    fn from(err: Error<ErrorKindCrypt>) -> Self {
        Self {
            kind: ErrorKind::Crypt(err.kind),
            code: err.code,
            message: err.message,
        }
    }
}

macro_rules! internal {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Internal,
            code: 0,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use internal;

macro_rules! encoding {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Encoding,
            code: 0,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use encoding;

macro_rules! overflow {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Overflow,
            code: 0,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use overflow;

use crate::convert::str_bytes_len;

pub type Result<T> = std::result::Result<T, Error<ErrorKind>>;
pub type CryptResult<T> = std::result::Result<T, Error<ErrorKindCrypt>>;

pub(crate) struct Status {
    inner: *mut sys::mongocrypt_status_t,
}

impl Status {
    pub(crate) fn new() -> Self {
        Self { inner: unsafe { sys::mongocrypt_status_new() } }
    }

    pub(crate) fn from_native(inner: *mut sys::mongocrypt_status_t) -> Self {
        Self { inner }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_status_t {
        self.inner
    }

    pub(crate) fn check(&self) -> Result<()> {
        let typ = unsafe { sys::mongocrypt_status_type(self.inner) };
        let kind = match typ {
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_OK => return Ok(()),
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT => ErrorKindCrypt::Client,
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS => ErrorKindCrypt::Kms,
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE => ErrorKindCrypt::CsFle,
            _ => return Err(internal!("unhandled status type {}", typ)),
        };
        let code = unsafe { sys::mongocrypt_status_code(self.inner) };
        let message_ptr = unsafe { sys::mongocrypt_status_message(self.inner, ptr::null_mut()) };
        let message = if message_ptr == ptr::null_mut() {
            None
        } else {
            let c_message = unsafe { CStr::from_ptr(message_ptr) };
            let message = c_message
                .to_str()
                .map_err(|err| {
                    encoding!("invalid status message: {}", err)
                })?;
            Some(message.to_string())
        };
        Err(Error { kind: ErrorKind::Crypt(kind), code, message })
    }

    pub(crate) fn set(&mut self, err: &Error<ErrorKindCrypt>) -> Result<()> {
        let typ = match err.kind {
            ErrorKindCrypt::Client => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
            ErrorKindCrypt::Kms => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS,
            ErrorKindCrypt::CsFle => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE,
        };
        let (message_ptr, message_len) = match &err.message {
            Some(message) => {
                let (ptr, len) = str_bytes_len(&message)?;
                (ptr, len + 1)
            }
            None => (ptr::null(), 0),
        };
        unsafe {
            sys::mongocrypt_status_set(self.inner, typ, err.code, message_ptr, message_len);
        }
        Ok(())
    }

    pub(crate) fn as_error(&self) -> Error<ErrorKind> {
        match self.check() {
            Err(e) => e,
            _ => internal!("expected error status, got ok")
        }
    }
}

impl Drop for Status {
    fn drop(&mut self) {
        unsafe { sys::mongocrypt_status_destroy(self.inner); }
    }
}

pub(crate) trait HasStatus {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t);

    fn status(&self) -> Status {
        let out = Status::new();
        unsafe { self.native_status(out.native()); }
        out
    }
}