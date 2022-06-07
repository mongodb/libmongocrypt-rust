use std::{ffi::CStr, ptr, path::Path};

use binary::{BinaryRef, Binary};
use bson::Document;
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

    pub fn log_handler<F>(mut self, handler: F) -> Result<Self>
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
        unsafe {
            if !sys::mongocrypt_setopt_log_handler(self.inner, Some(log_shim), handler_ptr) {
                return self.status_error();
            }
        }
        
        // Now that the handler's successfully set, store it so it gets dealloced on drop.
        self.log_handler = Some(handler);
        Ok(self)
    }

    pub fn kms_provider_aws(self, aws_access_key_id: &str, aws_secret_access_key: &str) -> Result<Self> {
        let key_bytes = aws_access_key_id.as_bytes();
        let secret_bytes = aws_secret_access_key.as_bytes();
        unsafe {
            if !sys::mongocrypt_setopt_kms_provider_aws(
                self.inner,
                key_bytes.as_ptr() as *const i8,
                key_bytes.len().try_into().map_err(|e| error::internal!("size overflow: {}", e))?,
                secret_bytes.as_ptr() as *const i8,
                secret_bytes.len().try_into().map_err(|e| error::internal!("size overflow: {}", e))?,
            ) {
                return self.status_error();
            }
        }
        Ok(self)
    }

    pub fn kms_provider_local(self, key: &[u8]) -> Result<Self> {
        let bin = BinaryRef::new(key);
        unsafe {
            if !sys::mongocrypt_setopt_kms_provider_local(
                self.inner,
                bin.inner(),
            ) {
                return self.status_error();
            }
        }
        Ok(self)
    }

    pub fn kms_providers(self, kms_providers: &Document) -> Result<Self> {
        let binary = doc_binary(kms_providers)?;
        unsafe {
            if !sys::mongocrypt_setopt_kms_providers(self.inner, binary.inner()) {
                return self.status_error();
            }
        }
        Ok(self)
    }

    pub fn schema_map(self, schema_map: &Document) -> Result<Self> {
        let binary = doc_binary(schema_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_schema_map(self.inner, binary.inner()) {
                return self.status_error();
            }
        }
        Ok(self)
    }

    pub fn encrypted_field_config_map(self, efc_map: &Document) -> Result<Self> {
        let binary = doc_binary(efc_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_encrypted_field_config_map(self.inner, binary.inner()) {
                return self.status_error();
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

    pub fn build(mut self) -> Result<MongoCrypt> {
        let ok = unsafe { sys::mongocrypt_init(self.inner) };
        if !ok {
            return self.status_error();
        }
        let out = MongoCrypt {
            inner: self.inner,
            _log_handler: self.log_handler.take(),
        };
        self.inner = ptr::null_mut();
        Ok(out)
    }

    fn status_error<T>(&self) -> Result<T> {
        let status = error::Status::new();
        unsafe { sys::mongocrypt_status(self.inner, status.inner()) };
        status.as_error()
    }
}

fn doc_binary(doc: &Document) -> Result<Binary> {
    let mut bytes = vec![];
    doc.to_writer(&mut bytes).map_err(|e| error::internal!("failure serializing doc: {}", e))?;
    Ok(Binary::new(bytes))
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::prelude::OsStrExt;

    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    // This is correct for Windows because libmongocrypt internally converts
    // from utf8 to utf16 on that platform.
    use error::Error;

    let s = path.to_str().ok_or_else(|| Error {
        kind: ErrorKind::Encoding,
        code: 0,
        message: Some(format!("could not utf-8 encode path {:?}", path)),
    })?;
    Ok(s.as_bytes().to_vec())
}

impl Drop for MongoCryptBuilder {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}

pub struct MongoCrypt {
    inner: *mut sys::mongocrypt_t,
    // Double-boxing is required because the inner `Box<dyn ..>` is represented as a fat pointer; the outer one is a thin pointer convertible to *c_void.
    _log_handler: Option<Box<LogCb>>,
}

impl Drop for MongoCrypt {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}

impl MongoCrypt {
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
}