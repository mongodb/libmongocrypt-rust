use std::{ptr, ffi::CStr, marker::PhantomData};

use bson::{doc, Document, RawDocument};
use mongocrypt_sys as sys;

use crate::{binary::{BinaryRef, Binary}, error::{HasStatus, Result, self}, convert::{doc_binary, str_bytes_len, rawdoc, c_str}};

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
    pub(crate) fn new(inner: *mut sys::mongocrypt_ctx_t) -> Self {
        Self { inner }
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

impl Ctx {
    pub fn state(&self) -> Result<State> {
        State::from_native(unsafe {
            sys::mongocrypt_ctx_state(self.inner)
        })
    }

    pub fn mongo_op(&self) -> Result<&RawDocument> {
        // Safety: `mongocrypt_ctx_mongo_op` updates the passed-in `Binary` to point to a chunk of
        // BSON with the same lifetime as the underlying `Ctx`.  The `Binary` itself does not own
        // the memory, and gets cleaned up at the end of the unsafe block.  Lifetime inference on
        // the return type binds `op_bytes` to the same lifetime as `&self`, which is the correct
        // one.
        let op_bytes = unsafe {
            let bin = Binary::new();
            if !sys::mongocrypt_ctx_mongo_op(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()
        };
        rawdoc(op_bytes)
    }

    pub fn mongo_feed(&mut self, reply: &RawDocument) -> Result<()> {
        let bin = BinaryRef::new(reply.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_mongo_feed(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    pub fn mongo_done(&mut self) -> Result<()> {
        unsafe {
            if !sys::mongocrypt_ctx_mongo_done(self.inner) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    pub fn kms_scope(&self) -> KmsScope {
        KmsScope { ctx: self, done: false }
    }

    pub fn kms_done(&mut self, mut scope: KmsScope) -> Result<()> {
        scope.done = true;
        unsafe {
            if !sys::mongocrypt_ctx_kms_done(self.inner) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum State {
    Error,
    NeedMongoCollinfo,
    NeedMongoMarkings,
    NeedMongoKeys,
    NeedKms,
    NeedKmsCredentials,
    Ready,
    Done,
}

impl State {
    fn from_native(state: sys::mongocrypt_ctx_state_t) -> Result<Self> {
        match state {
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_ERROR => Ok(Self::Error),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO => Ok(Self::NeedMongoCollinfo),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_MARKINGS => Ok(Self::NeedMongoMarkings),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_KEYS => Ok(Self::NeedMongoKeys),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS => Ok(Self::NeedKms),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS => Ok(Self::NeedKmsCredentials),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_READY => Ok(Self::Ready),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_DONE => Ok(Self::Done),
            _ => Err(error::internal!("unexpected ctx state {}", state)),
        }
    }
}

pub struct KmsScope<'ctx> {
    ctx: &'ctx Ctx,
    done: bool,
}

impl<'ctx> KmsScope<'ctx> {
    pub fn next_kms_ctx(&mut self) -> Option<KmsCtx> {
        let inner = unsafe {
            sys::mongocrypt_ctx_next_kms_ctx(self.ctx.inner)
        };
        if inner == ptr::null_mut() {
            return None;
        }
        Some(KmsCtx { inner, _marker: PhantomData })
    }
}

impl<'ctx> Drop for KmsScope<'ctx> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if !self.done {
            panic!("KmsScope dropped without calling kms_done");
        }
    }
}

pub struct KmsCtx<'scope> {
    inner: *mut sys::mongocrypt_kms_ctx_t,
    _marker: PhantomData<&'scope mut ()>,
}

impl<'scope> HasStatus for KmsCtx<'scope> {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_kms_ctx_status(self.inner, status);
    }
}

impl<'scope> KmsCtx<'scope> {
    pub fn message(&self) -> Result<&'scope RawDocument> {
        // Safety: the message referenced has a lifetime that's valid until kms_done is called,
        // which can't happen without ending 'scope.
        let bytes = unsafe {
            let bin = Binary::new();
            if !sys::mongocrypt_kms_ctx_message(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()
        };
        rawdoc(bytes)
    }

    pub fn endpoint(&self) -> Result<&'scope str> {
        let mut ptr: *const ::std::os::raw::c_char = ptr::null();
        unsafe {
            if !sys::mongocrypt_kms_ctx_endpoint(self.inner, &mut ptr as *mut *const ::std::os::raw::c_char) {
                return Err(self.status().as_error());
            }
            c_str(ptr)
        }
    }

    pub fn bytes_needed(&self) -> u32 {
        unsafe {
            sys::mongocrypt_kms_ctx_bytes_needed(self.inner)
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let bin = BinaryRef::new(bytes);
        unsafe {
            if !sys::mongocrypt_kms_ctx_feed(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    pub fn get_kms_provider(&self) -> Result<&'static str> {
        unsafe {
            let ptr = sys::mongocrypt_kms_ctx_get_kms_provider(self.inner, ptr::null_mut());
            c_str(ptr)
        }
    }
}