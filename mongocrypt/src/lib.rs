use std::{borrow::Borrow, ffi::CStr, path::Path, ptr, sync::Mutex};

use bson::Document;
#[cfg(test)]
use convert::str_bytes_len;
use convert::{doc_binary, path_cstring};
use ctx::CtxBuilder;
use mongocrypt_sys as sys;

mod binary;
mod convert;
pub mod ctx;
pub mod error;
mod hooks;
mod native;
#[cfg(test)]
mod test;

use error::{HasStatus, Result};
pub use hooks::*;
use native::OwnedPtr;
use once_cell::sync::Lazy;

/// Returns the version string for libmongocrypt.
pub fn version() -> &'static str {
    let c_version = unsafe { CStr::from_ptr(sys::mongocrypt_version(ptr::null_mut())) };
    // Unwrap safety: the validity of this parse is enforced by unit test in mongocrypt-sys.
    c_version.to_str().unwrap()
}

/// Returns true if libmongocrypt was built with native crypto support.
pub fn is_crypto_available() -> bool {
    unsafe { sys::mongocrypt_is_crypto_available() }
}

pub struct CryptBuilder {
    inner: OwnedPtr<sys::mongocrypt_t>,
    cleanup: Vec<Box<dyn std::any::Any>>,
}

impl HasStatus for CryptBuilder {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_status(*self.inner.borrow(), status);
    }
}

// This works around a possible race condition in mongocrypt [de]initialization; see RUST-1578 for details.
static CRYPT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

unsafe extern "C" fn mongocrypt_destroy_locked(crypt: *mut sys::mongocrypt_t) {
    let _guard = CRYPT_LOCK.lock().unwrap();
    sys::mongocrypt_destroy(crypt);
}

impl CryptBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: OwnedPtr::steal(unsafe { sys::mongocrypt_new() }, mongocrypt_destroy_locked),
            cleanup: vec![],
        }
    }

    /// Configure an AWS KMS provider.
    ///
    /// This has been superseded by the more flexible `kms_providers` method.
    ///
    /// * `aws_access_key_id` - The AWS access key ID used to generate KMS messages.
    /// * `aws_secret_access_key` - The AWS secret access key used to generate KMS messages.
    #[cfg(test)]
    pub(crate) fn kms_provider_aws(
        self,
        aws_access_key_id: &str,
        aws_secret_access_key: &str,
    ) -> Result<Self> {
        let (key_bytes, key_len) = str_bytes_len(aws_access_key_id)?;
        let (secret_bytes, secret_len) = str_bytes_len(aws_secret_access_key)?;
        unsafe {
            if !sys::mongocrypt_setopt_kms_provider_aws(
                *self.inner.borrow(),
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

    /// Configure KMS providers with a BSON document.
    ///
    /// * `kms_providers` - A BSON document mapping the KMS provider names
    /// to credentials. Set a KMS provider value to an empty document to supply
    /// credentials on-demand with `Ctx::provide_kms_providers`.
    pub fn kms_providers(self, kms_providers: &Document) -> Result<Self> {
        let mut binary = doc_binary(kms_providers)?;
        unsafe {
            if !sys::mongocrypt_setopt_kms_providers(*self.inner.borrow(), *binary.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set a local schema map for encryption.
    ///
    /// * `schema_map` - A BSON document representing the schema map supplied by
    /// the user. The keys are collection namespaces and values are JSON schemas.
    pub fn schema_map(self, schema_map: &Document) -> Result<Self> {
        let mut binary = doc_binary(schema_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_schema_map(*self.inner.borrow(), *binary.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set a local EncryptedFieldConfigMap for encryption.
    ///
    /// * `efc_map` - A BSON document representing the EncryptedFieldConfigMap
    /// supplied by the user. The keys are collection namespaces and values are
    /// EncryptedFieldConfigMap documents.
    pub fn encrypted_field_config_map(self, efc_map: &Document) -> Result<Self> {
        let mut binary = doc_binary(efc_map)?;
        unsafe {
            if !sys::mongocrypt_setopt_encrypted_field_config_map(
                *self.inner.borrow(),
                *binary.native(),
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Append an additional search directory to the search path for loading
    /// the crypt_shared dynamic library.
    ///
    /// If the leading element of
    /// the path is the literal string "$ORIGIN", that substring will be replaced
    /// with the directory path containing the executable libmongocrypt module. If
    /// the path string is literal "$SYSTEM", then libmongocrypt will defer to the
    /// system's library resolution mechanism to find the crypt_shared library.
    ///
    /// If no crypt_shared dynamic library is found in any of the directories
    /// specified by the search paths loaded here, `build` will still
    /// succeed and continue to operate without crypt_shared.
    ///
    /// The search paths are searched in the order that they are appended. This
    /// allows one to provide a precedence in how the library will be discovered. For
    /// example, appending known directories before appending "$SYSTEM" will allow
    /// one to supersede the system's installed library, but still fall-back to it if
    /// the library wasn't found otherwise. If one does not ever append "$SYSTEM",
    /// then the system's library-search mechanism will never be consulted.
    ///
    /// If an absolute path to the library is specified using
    /// `set_crypt_shared_lib_path_override`, then paths
    /// appended here will have no effect.
    pub fn append_crypt_shared_lib_search_path(self, path: &Path) -> Result<Self> {
        let tmp = path_cstring(path)?;
        unsafe {
            sys::mongocrypt_setopt_append_crypt_shared_lib_search_path(
                *self.inner.borrow(),
                tmp.as_ptr(),
            );
        }
        Ok(self)
    }

    /// Set a single override path for loading the crypt_shared dynamic
    /// library.
    ///
    /// If the leading element of the path is the literal string
    /// `$ORIGIN`, that substring will be replaced with the directory path containing
    /// the executable libmongocrypt module.
    ///
    /// This function will do no IO nor path validation. All validation will
    /// occur during the call to `build`.
    ///
    /// If a crypt_shared library path override is specified here, then no
    /// paths given to `append_crypt_shared_lib_search_path`
    /// will be consulted when opening the crypt_shared library.
    ///
    /// If a path is provided via this API and `build` fails to
    /// initialize a valid crypt_shared library instance for the path specified, then
    /// the initialization will fail with an error.
    pub fn set_crypt_shared_lib_path_override(self, path: &Path) -> Result<Self> {
        let tmp = path_cstring(path)?;
        unsafe {
            sys::mongocrypt_setopt_set_crypt_shared_lib_path_override(
                *self.inner.borrow(),
                tmp.as_ptr(),
            );
        }
        Ok(self)
    }

    /// Opt-into handling the MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS state.
    ///
    /// If set, before entering the MONGOCRYPT_CTX_NEED_KMS state,
    /// contexts may enter the MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS state
    /// and then wait for credentials to be supplied through
    /// @ref mongocrypt_ctx_provide_kms_providers.
    ///
    /// A context will only enter MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS
    /// if an empty document was set for a KMS provider in @ref
    /// mongocrypt_setopt_kms_providers.
    pub fn use_need_kms_credentials_state(self) -> Self {
        unsafe {
            sys::mongocrypt_setopt_use_need_kms_credentials_state(*self.inner.borrow());
        }
        self
    }

    /// Opt-into handling the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB state.
    ///
    /// A context enters the MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB state when
    /// processing a `bulkWrite` command. The target database of the `bulkWrite` may differ from the command database
    /// ("admin").
    pub fn use_need_mongo_collinfo_with_db_state(self) -> Self {
        unsafe {
            sys::mongocrypt_setopt_use_need_mongo_collinfo_with_db_state(*self.inner.borrow());
        }
        self
    }

    /// Opt-into skipping query analysis.
    ///
    /// If opted in:
    /// * The crypt_shared library will not attempt to be loaded.
    /// * A `Ctx` will never enter the `State::NeedMarkings` state.
    pub fn bypass_query_analysis(self) -> Self {
        unsafe {
            sys::mongocrypt_setopt_bypass_query_analysis(*self.inner.borrow());
        }
        self
    }

    /// Opt-into use of Queryable Encryption Range V2 protocol.
    pub fn use_range_v2(self) -> Result<Self> {
        let ok = unsafe { sys::mongocrypt_setopt_use_range_v2(*self.inner.borrow()) };
        if !ok {
            return Err(self.status().as_error());
        }
        Ok(self)
    }

    pub fn retry_kms(self, enable: bool) -> Result<Self> {
        unsafe {
            let ok = sys::mongocrypt_setopt_retry_kms(*self.inner.borrow(), enable);
            if !ok {
                return Err(self.status().as_error())
            }
        }
        Ok(self)
    }

    pub fn build(mut self) -> Result<Crypt> {
        let _guard = CRYPT_LOCK.lock().unwrap();

        let ok = unsafe { sys::mongocrypt_init(*self.inner.borrow()) };
        if !ok {
            return Err(self.status().as_error());
        }
        Ok(Crypt {
            inner: self.inner,
            _cleanup: std::mem::take(&mut self.cleanup),
        })
    }
}

/// The top-level handle to libmongocrypt.
///
/// Create a `Crypt` handle to perform operations within libmongocrypt:
/// encryption, decryption, registering log callbacks, etc.
///
/// Multiple `Crypt` handles may be created.
pub struct Crypt {
    inner: OwnedPtr<sys::mongocrypt_t>,
    _cleanup: Vec<Box<dyn std::any::Any>>,
}

unsafe impl Send for Crypt {}
unsafe impl Sync for Crypt {}

impl Crypt {
    pub fn builder() -> CryptBuilder {
        CryptBuilder::new()
    }

    /// Obtain a version string of the loaded crypt_shared dynamic
    /// library, if available.
    ///
    /// For a numeric value that can be compared against, use `shared_lib_version`.
    pub fn shared_lib_version_string(&self) -> Option<String> {
        let s_ptr = unsafe {
            sys::mongocrypt_crypt_shared_lib_version_string(
                *self.inner.borrow_const(),
                ptr::null_mut(),
            )
        };
        if s_ptr.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(s_ptr) };
        Some(s.to_string_lossy().to_string())
    }

    /// Obtain a 64-bit constant encoding the version of the loaded
    /// crypt_shared library, if available.
    ///
    /// The version is encoded as four 16-bit numbers, from high to low:
    ///
    /// - Major version
    /// - Minor version
    /// - Revision
    /// - Reserved
    ///
    /// For example, version 6.2.1 would be encoded as: 0x0006'0002'0001'0000
    pub fn shared_lib_version(&self) -> Option<u64> {
        let out = unsafe { sys::mongocrypt_crypt_shared_lib_version(*self.inner.borrow_const()) };
        if out == 0 {
            return None;
        }
        Some(out)
    }

    pub fn ctx_builder(&self) -> CtxBuilder {
        CtxBuilder::steal(unsafe { sys::mongocrypt_ctx_new(*self.inner.borrow()) })
    }
}
