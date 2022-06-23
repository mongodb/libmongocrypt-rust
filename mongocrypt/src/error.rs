use std::{
    borrow::Borrow,
    ffi::CStr,
    fmt::{Debug, Display},
    ptr,
};

use mongocrypt_sys as sys;

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub code: Option<u32>,
    pub message: Option<String>,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(code) = &self.code {
            write!(f, " ({})", code)?;
        }
        if let Some(s) = &self.message {
            write!(f, ": {}", s)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    // These correspond to errors from libmongocrypt
    Client,
    Kms,
    CsFle,
    // These are produced in this crate
    Encoding,
    Overflow,
    Internal,
    // Forward compatibility
    Other(sys::mongocrypt_status_type_t),
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Self {
        overflow!("size overflow: {}", err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        encoding!("invalid string: {}", err)
    }
}

macro_rules! internal {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Internal,
            code: None,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use internal;

macro_rules! encoding {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Encoding,
            code: None,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use encoding;

macro_rules! overflow {
    ($($arg:tt)*) => {{
        crate::error::Error {
            kind: crate::error::ErrorKind::Overflow,
            code: None,
            message: Some(format!($($arg)*)),
        }
    }}
}
pub(crate) use overflow;

use crate::{convert::str_bytes_len, native::OwnedPtr};

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Status {
    inner: OwnedPtr<sys::mongocrypt_status_t>,
}

impl Status {
    pub(crate) fn new() -> Self {
        Self::from_native(unsafe { sys::mongocrypt_status_new() })
    }

    pub(crate) fn from_native(inner: *mut sys::mongocrypt_status_t) -> Self {
        Self {
            inner: OwnedPtr::new(inner, sys::mongocrypt_status_destroy),
        }
    }

    pub(crate) fn native(&self) -> &*mut sys::mongocrypt_status_t {
        self.inner.borrow()
    }

    pub(crate) fn set(&mut self, err: &Error) -> Result<()> {
        let inner_err;
        // Reborrow to help the borrow checker accept the lifetime of the assignment in the fallthrough.
        let mut err = &*err;
        let typ = match err.kind {
            ErrorKind::Client => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
            ErrorKind::Kms => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS,
            ErrorKind::CsFle => sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE,
            _ => {
                inner_err = Error {
                    kind: ErrorKind::Client,
                    code: err.code,
                    message: err
                        .message
                        .as_ref()
                        .map(|s| format!("{:?}: {}", err.kind, s)),
                };
                err = &inner_err;
                sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT
            }
        };
        let (message_ptr, message_len) = match &err.message {
            Some(message) => {
                let (ptr, len) = str_bytes_len(message)?;
                (ptr, len + 1)
            }
            None => (ptr::null(), 0),
        };
        let code = match err.code {
            Some(c) => c,
            None => 0,
        };
        unsafe {
            sys::mongocrypt_status_set(*self.native(), typ, code, message_ptr, message_len);
        }
        Ok(())
    }

    pub(crate) fn as_result(&self) -> Result<()> {
        let typ = unsafe { sys::mongocrypt_status_type(*self.native()) };
        let kind = match typ {
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_OK => return Ok(()),
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT => ErrorKind::Client,
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_KMS => ErrorKind::Kms,
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CSFLE => ErrorKind::CsFle,
            _ => ErrorKind::Other(typ),
        };
        let code = unsafe { sys::mongocrypt_status_code(*self.native()) };
        let message_ptr =
            unsafe { sys::mongocrypt_status_message(*self.native(), ptr::null_mut()) };
        let message = if message_ptr.is_null() {
            None
        } else {
            let c_message = unsafe { CStr::from_ptr(message_ptr) };
            let message = c_message
                .to_str()
                .map_err(|err| encoding!("invalid status message: {}", err))?;
            Some(message.to_string())
        };
        Err(Error {
            kind,
            code: Some(code),
            message,
        })
    }

    pub(crate) fn as_error(&self) -> Error {
        match self.as_result() {
            Err(e) => e,
            _ => internal!("expected error status, got ok"),
        }
    }
}

pub(crate) trait HasStatus {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t);

    fn status(&self) -> Status {
        let out = Status::new();
        unsafe {
            self.native_status(*out.native());
        }
        out
    }
}
