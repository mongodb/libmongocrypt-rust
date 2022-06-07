use std::{ffi::CStr, ptr, path::Path};

use binary::{BinaryRef, Binary};
use bson::{Document, Uuid, doc};
use mongocrypt_sys as sys;

mod binary;
#[cfg(test)]
mod test;
pub mod error;

use error::{Result, Status};

/// Returns the version string for libmongocrypt.
pub fn version() -> &'static str {
    let c_version = unsafe { CStr::from_ptr(sys::mongocrypt_version(ptr::null_mut())) };
    // Unwrap safety: the validity of this parse is enforced by unit test in mongocrypt-sys.
    c_version.to_str().unwrap()
}

trait HasStatus {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t);

    fn status(&self) -> Status {
        let out = Status::new();
        unsafe { self.native_status(out.native()); }
        out
    }
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

pub struct CryptBuilder {
    inner: *mut sys::mongocrypt_t,
    log_handler: Option<Box<LogCb>>,
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

        // Double-boxing is required because the inner `Box<dyn ..>` is represented as a fat pointer; the outer one is a thin pointer convertible to *c_void.
        let handler: Box<Box<LogCb>> = Box::new(Box::new(handler));
        let handler_ptr = &*handler as *const Box<LogCb> as *mut std::ffi::c_void;
        unsafe {
            if !sys::mongocrypt_setopt_log_handler(self.inner, Some(log_shim), handler_ptr) {
                return Err(self.status().as_error());
            }
        }
        
        // Now that the handler's successfully set, store it so it gets dealloced on drop.
        self.log_handler = Some(handler);
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

    pub fn build(mut self) -> Result<Crypt> {
        let ok = unsafe { sys::mongocrypt_init(self.inner) };
        if !ok {
            return Err(self.status().as_error());
        }
        let out = Crypt {
            inner: self.inner,
            _log_handler: self.log_handler.take(),
        };
        self.inner = ptr::null_mut();
        Ok(out)
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

fn str_bytes_len(s: &str) -> Result<(*const i8, i32)> {
    Ok((
        s.as_bytes().as_ptr() as *const i8,
        s.as_bytes().len().try_into().map_err(|e| error::internal!("size overflow: {}", e))?
    ))
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
    _log_handler: Option<Box<LogCb>>,
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
}

pub struct CtxBuilder {
    inner: *mut sys::mongocrypt_ctx_t,
}

impl Drop for CtxBuilder {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe {
                sys::mongocrypt_ctx_destroy(self.inner);
            }
        }
    }
}

impl HasStatus for CtxBuilder {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(self.inner, status);
    }
}

impl CtxBuilder {
    pub fn new(crypt: &Crypt) -> Self {
        Self {
            inner: unsafe { sys::mongocrypt_ctx_new(crypt.inner) },
        }
    }

    pub fn key_id(self, key_id: &Uuid) -> Result<Self> {
        let bytes = key_id.bytes();
        let bin = BinaryRef::new(&bytes);
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_id(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn key_alt_name(self, key_alt_name: &str) -> Result<Self> {
        let bin = doc_binary(&doc! { "keyAltName": key_alt_name })?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_alt_name(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn key_material(self, key_material: &[u8]) -> Result<Self> {
        let bson_bin = bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: key_material.to_vec(),
        };
        let bin = doc_binary(&doc! { "keyMaterial": bson_bin })?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_material(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn algorithm(self, algorithm: Algorithm) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_algorithm(self.inner, algorithm.c_str().as_ptr(), -1) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn masterkey_aws(self, region: &str, cmk: &str) -> Result<Self> {
        let (region_bytes, region_len) = str_bytes_len(region)?;
        let (cmk_bytes, cmk_len) = str_bytes_len(cmk)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_aws(
                self.inner,
                region_bytes,
                region_len,
                cmk_bytes,
                cmk_len,
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn masterkey_aws_endpoint(self, endpoint: &str) -> Result<Self> {
        let (bytes, len) = str_bytes_len(endpoint)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_aws_endpoint(self.inner, bytes, len) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn masterkey_local(self) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_local(self.inner) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn key_encryption_key(self, key_encryption_key: &Document) -> Result<Self> {
        let bin = doc_binary(key_encryption_key)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_encryption_key(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            Ok(self)
        }
    }

    pub fn build_datakey(mut self) -> Result<Ctx> {
        unsafe {
            if !sys::mongocrypt_ctx_datakey_init(self.inner) {
                return Err(self.status().as_error());
            }
        }
        let out = Ctx { inner: self.inner };
        self.inner = ptr::null_mut();
        Ok(out)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Algorithm {
    AeadAes256CbcHmacSha512Deterministic,
    AeadAes256CbcHmacSha512Random,
}

impl Algorithm {
    fn c_str(&self) -> &'static CStr {
        let bytes: &[u8] = match self {
            Self::AeadAes256CbcHmacSha512Deterministic => b"AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic\0",
            Self::AeadAes256CbcHmacSha512Random => b"AEAD_AES_256_CBC_HMAC_SHA_512-Random\0",
        };
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

pub struct Ctx {
    inner: *mut sys::mongocrypt_ctx_t,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe {
                sys::mongocrypt_ctx_destroy(self.inner);
            }
        }
    }
}

impl HasStatus for Ctx {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(self.inner, status);
    }
}
