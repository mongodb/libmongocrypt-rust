#![allow(non_upper_case_globals)]

use std::{ffi::CStr, ptr};

use mongocrypt_sys as sys;

mod binary;
#[cfg(test)]
mod test;
pub mod error;

use error::Result;

/// Returns the version string for libmongocrypt.
pub fn version() -> &'static str {
    let c_version = unsafe { CStr::from_ptr(sys::mongocrypt_version(ptr::null_mut())) };
    // Unwrap safety: the validity of this parse is enforced by unit test in mongocrypt-sys.
    c_version.to_str().unwrap()
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum LogLevel {
    Fatal,
    Error,
    Warning,
    Info,
    Trace,
}

impl LogLevel {
    fn from_native(level: sys::mongocrypt_log_level_t) -> error::Result<Self> {
        match level {
            sys::mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_FATAL => Ok(Self::Fatal),
            sys::mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_ERROR => Ok(Self::Error),
            sys::mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_WARNING => Ok(Self::Warning),
            sys::mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_INFO => Ok(Self::Info),
            sys::mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_TRACE => Ok(Self::Trace),
            _ => Err(error::Error {
                kind: error::ErrorKind::Internal,
                code: 0,
                message: Some(format!("unhandled log level {}", level)),
            })
        }
    }
}

type LogCb = dyn Fn(LogLevel, &str);

pub struct MongoCryptBuilder {
    inner: *mut sys::mongocrypt_t,
    // Double-boxing is required because the inner `Box<dyn ..>` is represented as a fat pointer; the outer one is a thin pointer convertible to *c_void.
    log_handler: Option<Box<LogCb>>,
}

impl MongoCryptBuilder {
    pub fn new() -> Self {
        Self {
            inner: unsafe { sys::mongocrypt_new() },
            log_handler: None,
        }
    }

    pub fn log_handler<F>(&mut self, handler: F) -> Result<&mut Self>
        where F: Fn(LogLevel, &str) + 'static
    {
        extern "C" fn log_shim(
            c_level: sys::mongocrypt_log_level_t,
            c_message: *const ::std::os::raw::c_char,
            _message_len: u32,
            ctx: *mut ::std::os::raw::c_void,
        ) {
            let level = LogLevel::from_native(c_level).unwrap();
            let cs_message = unsafe { CStr::from_ptr(c_message) };
            let message = cs_message.to_string_lossy();
            // Safety: this pointer originates below with the same type and with a lifetime of that of the containing `MongoCrypt`.
            let handler: &Box<LogCb> = unsafe { std::mem::transmute(ctx) };
            handler(level, &message);
        }

        let handler: Box<Box<LogCb>> = Box::new(Box::new(handler));
        let handler_ptr = &*handler as *const Box<LogCb> as *mut std::ffi::c_void;
        let ok = unsafe { sys::mongocrypt_setopt_log_handler(self.inner, Some(log_shim), handler_ptr) };
        if !ok {
            let status = error::Status::new();
            unsafe { sys::mongocrypt_status(self.inner, status.inner()) };
            return status.as_error();
        }
        
        // Now that the handler's successfully set, store it so it gets dealloced on drop.
        self.log_handler = Some(handler);
        Ok(self)
    }
}

impl Drop for MongoCryptBuilder {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}