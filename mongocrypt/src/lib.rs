use std::{ffi::CStr, ptr, path::Path, io::Write};

use binary::BinaryRef;
use bson::Document;
use convert::{str_bytes_len, doc_binary, path_bytes};
use ctx::CtxBuilder;
use mongocrypt_sys as sys;

mod binary;
mod convert;
pub mod ctx;
#[cfg(test)]
mod test;
pub mod error;

use error::{Result, HasStatus, CryptResult};

use crate::{convert::{binary_bytes, binary_bytes_mut}, error::{Error, ErrorKind, Status}};

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

pub struct CryptBuilder {
    inner: *mut sys::mongocrypt_t,
    cleanup: Vec<Box<dyn std::any::Any>>,
}

impl HasStatus for CryptBuilder {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_status(self.inner, status);
    }
}

impl CryptBuilder {
    pub fn new() -> Self {
        Self {
            inner: unsafe { sys::mongocrypt_new() },
            cleanup: vec![],
        }
    }

    pub fn log_handler<F>(mut self, handler: F) -> Result<Self>
        where F: Fn(LogLevel, &str) + 'static
    {
        type LogCb = dyn Fn(LogLevel, &str);

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
            //let handler: &Box<LogCb> = unsafe { std::mem::transmute(ctx) };
            let handler = unsafe { &*(ctx as *const Box<LogCb>) };
            handler(level, &message);
        }

        // Double-boxing is required because the inner `Box<dyn ..>` is represented as a fat pointer; the outer one is a thin pointer convertible to *c_void.
        let handler: Box<Box<LogCb>> = Box::new(Box::new(handler));
        let handler_ptr = &*handler as *const Box<LogCb> as *mut std::ffi::c_void;
        unsafe {
            if !sys::mongocrypt_setopt_log_handler(self.inner, Some(log_shim), handler_ptr) {
                return Err(self.status().as_error());
            }
        }
        
        // Now that the handler's successfully set, store it so it gets cleaned up on drop.
        self.cleanup.push(handler);
        Ok(self)
    }

    pub fn kms_provider_aws(self, aws_access_key_id: &str, aws_secret_access_key: &str) -> Result<Self> {
        let (key_bytes, key_len) = str_bytes_len(aws_access_key_id)?;
        let (secret_bytes, secret_len) = str_bytes_len(aws_secret_access_key)?;
        unsafe {
            if !sys::mongocrypt_setopt_kms_provider_aws(
                self.inner,
                key_bytes,
                key_len,
                secret_bytes,
                secret_len,
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn kms_provider_local(self, key: &[u8]) -> Result<Self> {
        let bin = BinaryRef::new(key);
        unsafe {
            if !sys::mongocrypt_setopt_kms_provider_local(
                self.inner,
                bin.native(),
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn kms_providers(self, kms_providers: &Document) -> Result<Self> {
        let binary = doc_binary(kms_providers)?;
        unsafe {
            if !sys::mongocrypt_setopt_kms_providers(self.inner, binary.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn schema_map(self, schema_map: &Document) -> Result<Self> {
        let binary = doc_binary(schema_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_schema_map(self.inner, binary.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn encrypted_field_config_map(self, efc_map: &Document) -> Result<Self> {
        let binary = doc_binary(efc_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_encrypted_field_config_map(self.inner, binary.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn append_crypt_shared_lib_search_path(self, path: &Path) -> Result<Self> {
        let mut tmp = path_bytes(path)?;
        tmp.push(0);
        unsafe {
            sys::mongocrypt_setopt_append_crypt_shared_lib_search_path(self.inner, tmp.as_ptr() as *const i8);
        }
        Ok(self)
    }

    pub fn set_crypt_shared_lib_path_override(self, path: &Path) -> Result<Self> {
        let mut tmp = path_bytes(path)?;
        tmp.push(0);
        unsafe {
            sys::mongocrypt_setopt_set_crypt_shared_lib_path_override(self.inner, tmp.as_ptr() as *const i8);
        }
        Ok(self)
    }

    pub fn use_need_kms_credentials_state(self) -> Self {
        unsafe {
            sys::mongocrypt_setopt_use_need_kms_credentials_state(self.inner);
        }
        self
    }

    pub fn crypto_hooks(
        mut self,
        aes_256_cbc_encrypt: Option<impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()> + 'static>,
    ) -> Result<Self> {
        struct Hooks {
            aes_256_cbc_encrypt: Option<Box<dyn Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()>>>,
        }
        extern "C" fn crypto_shim(
            ctx: *mut ::std::os::raw::c_void,
            key: *mut sys::mongocrypt_binary_t,
            iv: *mut sys::mongocrypt_binary_t,
            in_: *mut sys::mongocrypt_binary_t,
            out: *mut sys::mongocrypt_binary_t,
            bytes_written: *mut u32,
            c_status: *mut sys::mongocrypt_status_t,
        ) -> bool {
            // Convenience scope for intermediate error propagation via `?`.
            let result = || -> Result<()> {
                let hooks = unsafe { &*(ctx as *const Hooks) };
                let key_bytes = unsafe { binary_bytes(key)? };
                let iv_bytes = unsafe { binary_bytes(iv)? };
                let in_bytes = unsafe { binary_bytes(in_)? };
                let mut out_bytes = unsafe { binary_bytes_mut(out)? };
                let buffer_len = out_bytes.len();
                let result = hooks.aes_256_cbc_encrypt.as_ref().unwrap()(key_bytes, iv_bytes, in_bytes, &mut out_bytes);
                let written = buffer_len - out_bytes.len();
                unsafe {
                    *bytes_written = written.try_into().map_err(|e| error::overflow!("buffer size overflow: {}", e))?;
                }
                result.map_err(Into::into)
            }();
            let err = match result {
                Ok(()) => return true,
                Err(Error { kind: ErrorKind::Crypt(ck), code, message }) => Error { kind: ck, code, message },
                // Map Rust-specific errors to Client with a message prefix.
                Err(Error { kind, code, message }) => Error {
                    kind: error::ErrorKindCrypt::Client,
                    code,
                    message: message.map(|s| format!("{:?}: {}", kind, s)),
                }
            };
            let mut status = Status::from_native(c_status);
            if let Err(status_err) = status.set(&err) {
                eprintln!("Failed to record error:\noriginal error = {:?}\nstatus error = {:?}", err, status_err);
                unsafe {
                    // Set a hardcoded status that can't fail.
                    sys::mongocrypt_status_set(
                        c_status,
                        sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
                        0,
                        b"Failed to record error, see logs for details\0".as_ptr() as *const i8,
                        -1,
                    );
                }
            }
            false
        }
        let aes_256_cbc_encrypt = aes_256_cbc_encrypt.map(|f| {
            let b: Box<dyn Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()>> = Box::new(f);
            b
        });
        let mut hooks = Box::new(Hooks {
            aes_256_cbc_encrypt,
        });
        // This is needed to give the typechecker a nudge in the right direction.
        fn opt_match<A, B>(a: &Option<A>, b: B) -> Option<B> {
            a.as_ref().map(|_| b)
        }
        unsafe {
            if !sys::mongocrypt_setopt_crypto_hooks(
                self.inner,
                opt_match(&hooks.aes_256_cbc_encrypt, crypto_shim),
                None,
                None,
                None,
                None,
                None,
                &mut *hooks as *mut Hooks as *mut std::ffi::c_void,
            ) {
                return Err(self.status().as_error());
            }
        }
        self.cleanup.push(hooks);
        Ok(self)
    }

    pub fn build(mut self) -> Result<Crypt> {
        let ok = unsafe { sys::mongocrypt_init(self.inner) };
        if !ok {
            return Err(self.status().as_error());
        }
        let out = Crypt {
            inner: self.inner,
            _cleanup: std::mem::take(&mut self.cleanup),
        };
        self.inner = ptr::null_mut();
        Ok(out)
    }
}

impl Drop for CryptBuilder {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}

pub struct Crypt {
    inner: *mut sys::mongocrypt_t,
    _cleanup: Vec<Box<dyn std::any::Any>>,
}

impl Drop for Crypt {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}

impl Crypt {
    pub fn shared_lib_version_string(&self) -> Option<String> {
        let s_ptr = unsafe { sys::mongocrypt_crypt_shared_lib_version_string(self.inner, ptr::null_mut()) };
        if s_ptr == ptr::null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(s_ptr) };
        Some(s.to_string_lossy().to_string())
    }

    pub fn shared_lib_version(&self) -> Option<u64> {
        let out = unsafe { sys::mongocrypt_crypt_shared_lib_version(self.inner) };
        if out == 0 {
            return None;
        }
        Some(out)
    }

    pub fn ctx_builder(&self) -> CtxBuilder {
        CtxBuilder::new(unsafe { sys::mongocrypt_ctx_new(self.inner) })
    }
}