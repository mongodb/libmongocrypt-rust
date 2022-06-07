use std::{ptr, ffi::CStr};

use bson::{doc, Document};
use mongocrypt_sys as sys;

use crate::{Crypt, binary::BinaryRef, error::{HasStatus, Result}, convert::{doc_binary, str_bytes_len}};

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

    pub fn key_id(self, key_id: &bson::Uuid) -> Result<Self> {
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

    fn into_ctx(mut self) -> Ctx {
        let out = Ctx { inner: self.inner };
        self.inner = ptr::null_mut();
        out
    }

    pub fn build_datakey(self) -> Result<Ctx> {
        unsafe {
            if !sys::mongocrypt_ctx_datakey_init(self.inner) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    pub fn build_encrypt(self, db: &str, cmd: &Document) -> Result<Ctx> {
        let (db_bytes, db_len) = str_bytes_len(db)?;
        let cmd_bin = doc_binary(cmd)?;
        unsafe {
            if !sys::mongocrypt_ctx_encrypt_init(self.inner, db_bytes, db_len, cmd_bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    pub fn build_explicit_encrypt(self, value: &bson::Bson) -> Result<Ctx> {
        let bin = doc_binary(&doc! { "v": value })?;
        unsafe {
            if !sys::mongocrypt_ctx_explicit_encrypt_init(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    pub fn build_decrypt(self, doc: &Document) -> Result<Ctx> {
        let bin = doc_binary(doc)?;
        unsafe {
            if !sys::mongocrypt_ctx_decrypt_init(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    pub fn build_explicit_decrypt(self, msg: &[u8]) -> Result<Ctx> {
        let bson_bin = bson::Binary {
            subtype: bson::spec::BinarySubtype::Encrypted,
            bytes: msg.into(),
        };
        let bin = doc_binary(&doc! { "v": bson_bin })?;
        unsafe {
            if !sys::mongocrypt_ctx_explicit_decrypt_init(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    pub fn build_rewrap_many_datakey(self, filter: &Document) -> Result<Ctx> {
        let bin = doc_binary(filter)?;
        unsafe {
            if !sys::mongocrypt_ctx_rewrap_many_datakey_init(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
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
