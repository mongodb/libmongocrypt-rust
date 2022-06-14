use std::{ffi::CStr, ptr, path::Path};

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
mod hooks;

use error::{Result, HasStatus};
pub use hooks::*;

/// Returns the version string for libmongocrypt.
pub fn version() -> &'static str {
    let c_version = unsafe { CStr::from_ptr(sys::mongocrypt_version(ptr::null_mut())) };
    // Unwrap safety: the validity of this parse is enforced by unit test in mongocrypt-sys.
    c_version.to_str().unwrap()
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

    pub fn bypass_query_analysis(self) -> Self {
        unsafe {
            sys::mongocrypt_setopt_bypass_query_analysis(self.inner);
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

unsafe impl Send for Crypt {}
unsafe impl Sync for Crypt {}

impl Drop for Crypt {
    fn drop(&mut self) {
        if self.inner != ptr::null_mut() {
            unsafe { sys::mongocrypt_destroy(self.inner); }
        }
    }
}

impl Crypt {
    pub fn builder() -> CryptBuilder {
        CryptBuilder::new()
    }

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