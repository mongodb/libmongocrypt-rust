use std::{ffi::CStr, ptr};

use mongocrypt_sys::*;

mod binary;
#[cfg(test)]
mod test;
pub mod error;

/// Returns the version string for libmongocrypt.
pub fn version() -> &'static str {
    let c_version = unsafe { CStr::from_ptr(mongocrypt_version(ptr::null_mut())) };
    // Unwrap safety: the validity of this parse is enforced by unit test in mongocrypt-sys.
    c_version.to_str().unwrap()
}

pub struct Status {
    inner: *mut mongocrypt_status_t,
}

impl Status {
    pub fn new() -> Self {
        Self { inner: unsafe { mongocrypt_status_new() } }
    }
}

pub enum StatusType {
    OK,
}

impl StatusType {
    fn from_native(status: mongocrypt_status_type_t) -> Option<Self> {
        match status {
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_OK => Some(StatusType::OK),
            _ => None,
        }
    }
}