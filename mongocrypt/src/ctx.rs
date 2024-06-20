use std::{borrow::Borrow, ffi::CStr, marker::PhantomData, ptr};

use bson::{rawdoc, Document, RawDocument};
use mongocrypt_sys as sys;
use serde::{Deserialize, Serialize};

use crate::{
    binary::{Binary, BinaryBuf, BinaryRef},
    convert::{doc_binary, rawdoc_view, str_bytes_len},
    error::{HasStatus, Result},
    native::OwnedPtr,
};

pub struct CtxBuilder {
    inner: OwnedPtr<sys::mongocrypt_ctx_t>,
}

impl HasStatus for CtxBuilder {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(*self.inner.borrow(), status);
    }
}

impl CtxBuilder {
    /// Takes ownership of the given pointer, and will destroy it on drop.
    pub(crate) fn steal(inner: *mut sys::mongocrypt_ctx_t) -> Self {
        Self {
            inner: OwnedPtr::steal(inner, sys::mongocrypt_ctx_destroy),
        }
    }

    /// Set the key id to use for explicit encryption.
    ///
    /// It is an error to set both this and the key alt name.
    ///
    /// * `key_id` - The binary corresponding to the _id (a UUID) of the data
    /// key to use from the key vault collection. Note, the UUID must be encoded with
    /// RFC-4122 byte order.
    pub fn key_id(self, key_id: &[u8]) -> Result<Self> {
        let bin = BinaryRef::new(key_id);
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_id(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the keyAltName to use for explicit encryption or
    /// data key creation.   
    ///
    /// For explicit encryption, it is an error to set both the keyAltName
    /// and the key id.
    ///
    /// For creating data keys, call this function repeatedly to set
    /// multiple keyAltNames.   
    pub fn key_alt_name(self, key_alt_name: &str) -> Result<Self> {
        let mut bin: BinaryBuf = rawdoc! { "keyAltName": key_alt_name }.into();
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_alt_name(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the keyMaterial to use for encrypting data.
    ///
    /// * `key_material` - The data encryption key to use.
    pub fn key_material(self, key_material: &[u8]) -> Result<Self> {
        let bson_bin = bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: key_material.to_vec(),
        };
        let mut bin: BinaryBuf = rawdoc! { "keyMaterial": bson_bin }.into();
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_material(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the algorithm used for encryption to either
    /// deterministic or random encryption. This value
    /// should only be set when using explicit encryption.
    pub fn algorithm(self, algorithm: Algorithm) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_algorithm(
                *self.inner.borrow(),
                algorithm.c_str().as_ptr(),
                -1,
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Identify the AWS KMS master key to use for creating a data key.
    ///
    /// This has been superseded by the more flexible `key_encryption_key`.
    ///
    /// * `region` - The AWS region.
    /// * `cmk` - The Amazon Resource Name (ARN) of the customer master key (CMK).
    #[cfg(test)]
    pub(crate) fn masterkey_aws(self, region: &str, cmk: &str) -> Result<Self> {
        let (region_bytes, region_len) = str_bytes_len(region)?;
        let (cmk_bytes, cmk_len) = str_bytes_len(cmk)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_aws(
                *self.inner.borrow(),
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

    /// Identify a custom AWS endpoint when creating a data key.
    /// This is used internally to construct the correct HTTP request
    /// (with the Host header set to this endpoint). This endpoint
    /// is persisted in the new data key, and will be returned via
    /// `KmsCtx::endpoint`.
    ///
    /// This has been superseded by the more flexible `key_encryption_key`.
    #[cfg(test)]
    pub(crate) fn masterkey_aws_endpoint(self, endpoint: &str) -> Result<Self> {
        let (bytes, len) = str_bytes_len(endpoint)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_aws_endpoint(*self.inner.borrow(), bytes, len)
            {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set key encryption key document for creating a data key or for rewrapping
    /// datakeys.   
    ///
    /// The following forms are accepted:
    ///
    /// AWS
    /// {
    ///    provider: "aws",
    ///    region: <string>,
    ///    key: <string>,
    ///    endpoint: <optional string>
    /// }
    ///
    /// Azure
    /// {
    ///    provider: "azure",
    ///    keyVaultEndpoint: <string>,
    ///    keyName: <string>,
    ///    keyVersion: <optional string>
    /// }
    ///
    /// GCP
    /// {
    ///    provider: "gcp",
    ///    projectId: <string>,
    ///    location: <string>,
    ///    keyRing: <string>,
    ///    keyName: <string>,
    ///    keyVersion: <string>,
    ///    endpoint: <optional string>
    /// }
    ///
    /// Local
    /// {
    ///    provider: "local"
    /// }
    ///
    /// KMIP
    /// {
    ///    provider: "kmip",
    ///    keyId: <optional string>
    ///    endpoint: <string>
    /// }
    pub fn key_encryption_key(self, key_encryption_key: &Document) -> Result<Self> {
        let mut bin = doc_binary(key_encryption_key)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_encryption_key(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
            Ok(self)
        }
    }

    /// Set the contention factor used for explicit encryption.
    /// The contention factor is only used for indexed Queryable Encryption.
    pub fn contention_factor(self, contention_factor: i64) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_contention_factor(
                *self.inner.borrow(),
                contention_factor,
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the index key id to use for explicit Queryable Encryption.
    ///
    /// If the index key id not set, the key id from `key_id` is used.
    ///
    /// * `key_id` - The _id (a UUID) of the data key to use from the key vault collection.
    pub fn index_key_id(self, key_id: &bson::Uuid) -> Result<Self> {
        let bytes = key_id.bytes();
        let bin = BinaryRef::new(&bytes);
        unsafe {
            if !sys::mongocrypt_ctx_setopt_index_key_id(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the query type to use for explicit Queryable Encryption.
    pub fn query_type(self, query_type: &str) -> Result<Self> {
        let (s, len) = str_bytes_len(query_type)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_query_type(*self.inner.borrow(), s, len) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set options for explicit encryption with [`Algorithm::Range`].
    ///
    /// `options` is a document of the form:
    /// {
    ///    "min": Optional<BSON value>,
    ///    "max": Optional<BSON value>,
    ///    "sparsity": Int64,
    ///    "precision": Optional<Int32>,
    ///    "trimFactor": Optional<Int32>
    /// }
    pub fn algorithm_range(self, options: Document) -> Result<Self> {
        let mut bin = doc_binary(&options)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_algorithm_range(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    fn into_ctx(self) -> Ctx {
        Ctx { inner: self.inner }
    }

    /// Initialize a context to create a data key.
    pub fn build_datakey(self) -> Result<Ctx> {
        unsafe {
            if !sys::mongocrypt_ctx_datakey_init(*self.inner.borrow()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Initialize a context for encryption.
    ///
    /// * `db` - The database name.
    /// * `cmd` - The BSON command to be encrypted.
    pub fn build_encrypt(self, db: &str, cmd: &RawDocument) -> Result<Ctx> {
        let (db_bytes, db_len) = str_bytes_len(db)?;
        let cmd_bin = BinaryRef::new(cmd.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_encrypt_init(
                *self.inner.borrow(),
                db_bytes,
                db_len,
                *cmd_bin.native(),
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Explicit helper method to encrypt a single BSON object. Contexts
    /// created for explicit encryption will not go through mongocryptd.
    ///
    /// To specify a key_id, algorithm, or iv to use, please use the
    /// corresponding methods before calling this.
    ///
    /// An error is returned if FLE 1 and Queryable Encryption incompatible options
    /// are set.
    ///
    /// * `value` - the plaintext BSON value.
    pub fn build_explicit_encrypt(self, value: bson::RawBson) -> Result<Ctx> {
        let mut bin: BinaryBuf = rawdoc! { "v": value }.into();
        unsafe {
            if !sys::mongocrypt_ctx_explicit_encrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Explicit helper method to encrypt a Match Expression or Aggregate Expression.
    /// Contexts created for explicit encryption will not go through mongocryptd.
    /// Requires query_type to be "range" or "rangePreview".
    ///
    /// NOTE: "rangePreview" is experimental only and is not intended for public use.
    /// API for "rangePreview" may be removed in a future release.
    ///
    /// This method expects the passed-in BSON to be one of these forms:
    ///
    /// 1. A Match Expression of this form:
    ///    {$and: [{<field>: {<op>: <value1>, {<field>: {<op>: <value2> }}]}
    /// 2. An Aggregate Expression of this form:
    ///    {$and: [{<op>: [<fieldpath>, <value1>]}, {<op>: [<fieldpath>, <value2>]}]
    ///
    /// <op> may be $lt, $lte, $gt, or $gte.
    ///
    /// The value of "v" is expected to be the BSON value passed to a driver
    /// ClientEncryption.encryptExpression helper.
    ///
    /// Associated options for FLE 1:
    /// - [CtxBuilder::key_id]
    /// - [CtxBuilder::key_alt_name]
    /// - [CtxBuilder::algorithm]
    ///
    /// Associated options for Queryable Encryption:
    /// - [CtxBuilder::key_id]
    /// - [CtxBuilder::index_key_id]
    /// - [CtxBuilder::contention_factor]
    /// - [CtxBuilder::query_type]
    /// - [CtxBuilder::range_options]
    ///
    /// An error is returned if FLE 1 and Queryable Encryption incompatible options
    /// are set.
    pub fn build_explicit_encrypt_expression(self, value: bson::RawDocumentBuf) -> Result<Ctx> {
        let mut bin: BinaryBuf = rawdoc! { "v": value }.into();
        unsafe {
            if !sys::mongocrypt_ctx_explicit_encrypt_expression_init(
                *self.inner.borrow(),
                *bin.native(),
            ) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Initialize a context for decryption.
    ///
    /// * `doc` - The document to be decrypted.
    pub fn build_decrypt(self, doc: &RawDocument) -> Result<Ctx> {
        let bin = BinaryRef::new(doc.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_decrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Explicit helper method to decrypt a single BSON object.
    ///
    /// * `msg` - the encrypted BSON.
    pub fn build_explicit_decrypt(self, msg: &[u8]) -> Result<Ctx> {
        let bson_bin = bson::Binary {
            subtype: bson::spec::BinarySubtype::Encrypted,
            bytes: msg.into(),
        };
        let mut bin: BinaryBuf = rawdoc! { "v": bson_bin }.into();
        unsafe {
            if !sys::mongocrypt_ctx_explicit_decrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }

    /// Initialize a context to rewrap datakeys.
    ///
    /// * `filter` - The filter to use for the find command on the key vault
    /// collection to retrieve datakeys to rewrap.
    pub fn build_rewrap_many_datakey(self, filter: &RawDocument) -> Result<Ctx> {
        let bin = BinaryRef::new(filter.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_rewrap_many_datakey_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self.into_ctx())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Algorithm {
    Deterministic,
    Random,
    Indexed,
    Unindexed,
    #[deprecated]
    RangePreview,
    Range,
}

impl Algorithm {
    fn c_str(&self) -> &'static CStr {
        let bytes: &[u8] = match self {
            Self::Deterministic => b"AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic\0",
            Self::Random => b"AEAD_AES_256_CBC_HMAC_SHA_512-Random\0",
            Self::Indexed => b"Indexed\0",
            Self::Unindexed => b"Unindexed\0",
            #[allow(deprecated)]
            Self::RangePreview => b"RangePreview\0",
            Self::Range => b"Range\0",
        };
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

pub struct Ctx {
    inner: OwnedPtr<sys::mongocrypt_ctx_t>,
}

// Functions on `mongocrypt_ctx_t` are not threadsafe but do not rely on any thread-local state, so `Ctx` is `Send` but not `Sync`.
unsafe impl Send for Ctx {}

impl HasStatus for Ctx {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(*self.inner.borrow(), status);
    }
}

/// Manages the state machine for encryption or decryption.
impl Ctx {
    /// Get the current state of a context.
    pub fn state(&self) -> Result<State> {
        let s = unsafe { sys::mongocrypt_ctx_state(*self.inner.borrow()) };
        if s == sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_ERROR {
            return Err(self.status().as_error());
        }
        Ok(State::from_native(s))
    }

    /// Get BSON necessary to run the mongo operation when in `State::NeedMongo*` states.
    ///
    /// The returned value:
    /// * for `State::NeedMongoCollinfo[WithDb]`it is a listCollections filter.
    /// * for `State::NeedMongoKeys` it is a find filter.
    /// * for `State::NeedMongoMarkings` it is a command to send to mongocryptd.
    pub fn mongo_op(&self) -> Result<&RawDocument> {
        // Safety: `mongocrypt_ctx_mongo_op` updates the passed-in `Binary` to point to a chunk of
        // BSON with the same lifetime as the underlying `Ctx`.  The `Binary` itself does not own
        // the memory, and gets cleaned up at the end of the unsafe block.  Lifetime inference on
        // the return type binds `op_bytes` to the same lifetime as `&self`, which is the correct
        // one.
        let op_bytes = unsafe {
            let bin = Binary::new();
            if !sys::mongocrypt_ctx_mongo_op(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()?
        };
        rawdoc_view(op_bytes)
    }

    /// Get the database to run the mongo operation.
    ///
    /// Only applies for [`State::NeedMongoCollinfoWithDb`].
    pub fn mongo_db(&self) -> Result<&str> {
        let cptr = unsafe { sys::mongocrypt_ctx_mongo_db(*self.inner.borrow()) };
        if cptr.is_null() {
            return Err(self.status().as_error());
        }
        // Lifetime safety: the returned cstr is valid for the lifetime of the underlying `Ctx`.
        let cstr = unsafe { CStr::from_ptr(cptr) };
        Ok(cstr.to_str()?)
    }

    /// Feed a BSON reply or result when this context is in
    /// `State::NeedMongo*` states. This may be called multiple times
    /// depending on the operation.
    ///
    /// `reply` is a BSON document result being fed back for this operation.
    /// - For `State::NeedMongoCollinfo[WithDb]` it is a doc from a listCollections
    /// cursor. (Note, if listCollections returned no result, do not call this
    /// function.)
    /// - For `State::NeedMongoKeys` it is a doc from a find cursor.
    ///   (Note, if find returned no results, do not call this function.)
    /// - For `State::NeedMongoMarkings` it is a reply from mongocryptd.
    pub fn mongo_feed(&mut self, reply: &RawDocument) -> Result<()> {
        let bin = BinaryRef::new(reply.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_mongo_feed(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    /// Call when done feeding the reply (or replies) back to the context.
    pub fn mongo_done(&mut self) -> Result<()> {
        unsafe {
            if !sys::mongocrypt_ctx_mongo_done(*self.inner.borrow()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    /// Create a scope guard that provides handles to pending KMS requests.
    pub fn kms_scope(&mut self) -> KmsScope {
        KmsScope { ctx: self }
    }

    /// Call in response to the `State::NeedKmsCredentials` state
    /// to set per-context KMS provider settings. These follow the same format
    /// as `CryptBuilder::kms_providers`. If no keys are present in the
    /// BSON input, the KMS provider settings configured for the `Crypt`
    /// at initialization are used.
    pub fn provide_kms_providers(&mut self, kms_providers_definition: &RawDocument) -> Result<()> {
        let bin = BinaryRef::new(kms_providers_definition.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_provide_kms_providers(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    /// Perform the final encryption or decryption.
    ///
    /// If this context was initialized with `CtxBuilder::build_encrypt`, then
    /// this BSON is the (possibly) encrypted command to send to the server.
    ///
    /// If this context was initialized with `CtxBuilder::build_decrypt`, then
    /// this BSON is the decrypted result to return to the user.
    ///
    /// If this context was initialized with `CtxBuilder::build_explicit_encrypt`,
    /// then this BSON has the form { "v": (BSON binary) } where the BSON binary
    /// is the resulting encrypted value.
    ///
    /// If this context was initialized with `CtxBuilder::build_explicit_decrypt`,
    /// then this BSON has the form { "v": (BSON value) } where the BSON value
    /// is the resulting decrypted value.
    ///
    /// If this context was initialized with `CtxBuilder::build_datakey`, then
    /// this BSON is the document containing the new data key to be inserted into
    /// the key vault collection.
    ///
    /// If this context was initialized with `CtxBuilder::build_rewrap_many_datakey`,
    /// then this BSON has the form { "v": [(BSON document), ...] } where each BSON
    /// document in the array is a document containing a rewrapped datakey to be
    /// bulk-updated into the key vault collection.
    pub fn finalize(&mut self) -> Result<&RawDocument> {
        let bytes = unsafe {
            let bin = Binary::new();
            if !sys::mongocrypt_ctx_finalize(*self.inner.borrow(), *bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()?
        };
        rawdoc_view(bytes)
    }
}

/// Indicates the state of the `Ctx`. Each state requires
/// different handling. See [the integration
/// guide](https://github.com/mongodb/libmongocrypt/blob/master/integrating.md#state-machine)
/// for information on what to do for each state.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum State {
    NeedMongoCollinfo,
    NeedMongoCollinfoWithDb,
    NeedMongoMarkings,
    NeedMongoKeys,
    NeedKms,
    NeedKmsCredentials,
    Ready,
    Done,
    Other(sys::mongocrypt_ctx_state_t),
}

impl State {
    fn from_native(state: sys::mongocrypt_ctx_state_t) -> Self {
        match state {
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO => {
                Self::NeedMongoCollinfo
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO_WITH_DB => {
                Self::NeedMongoCollinfoWithDb
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_MARKINGS => {
                Self::NeedMongoMarkings
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_KEYS => Self::NeedMongoKeys,
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS => Self::NeedKms,
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS => {
                Self::NeedKmsCredentials
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_READY => Self::Ready,
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_DONE => Self::Done,
            other => Self::Other(other),
        }
    }
}

/// A scope bounding the processing of (potentially multiple) KMS handles.
pub struct KmsScope<'ctx> {
    ctx: &'ctx Ctx,
}

// Handling multiple KMS requests is threadsafe, so `KmsScope` can be both `Send` and `Sync`.
unsafe impl<'ctx> Send for KmsScope<'ctx> {}
unsafe impl<'ctx> Sync for KmsScope<'ctx> {}

// This is `Iterator`-like but does not impl that because it's encouraged for multiple `KmsCtx` to
// be retrieved and processed in parallel, as reflected in the `&self` shared reference rather than
// `Iterator`'s exclusive `next(&mut self)`.
impl<'ctx> KmsScope<'ctx> {
    /// Get the next KMS handle.
    ///
    /// Multiple KMS handles may be retrieved at once. Drivers may do this to fan
    /// out multiple concurrent KMS HTTP requests. Feeding multiple KMS requests
    /// is thread-safe.
    ///
    /// If KMS handles are being handled synchronously, the driver can reuse the same
    /// TLS socket to send HTTP requests and receive responses.
    pub fn next_kms_ctx(&self) -> Option<KmsCtx> {
        let inner = unsafe { sys::mongocrypt_ctx_next_kms_ctx(*self.ctx.inner.borrow()) };
        if inner.is_null() {
            return None;
        }
        Some(KmsCtx {
            inner,
            _marker: PhantomData,
        })
    }
}

impl<'ctx> Drop for KmsScope<'ctx> {
    fn drop(&mut self) {
        unsafe {
            // If this errors, it will show up in the next call to `ctx.status()` (or any other ctx call).
            sys::mongocrypt_ctx_kms_done(*self.ctx.inner.borrow());
        }
    }
}

/// Manages a single KMS HTTP request/response.
pub struct KmsCtx<'scope> {
    inner: *mut sys::mongocrypt_kms_ctx_t,
    _marker: PhantomData<&'scope mut ()>,
}

unsafe impl<'scope> Send for KmsCtx<'scope> {}
unsafe impl<'scope> Sync for KmsCtx<'scope> {}

impl<'scope> HasStatus for KmsCtx<'scope> {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_kms_ctx_status(self.inner, status);
    }
}

impl<'scope> KmsCtx<'scope> {
    /// Get the HTTP request message for a KMS handle.
    pub fn message(&self) -> Result<&'scope [u8]> {
        // Safety: the message referenced has a lifetime that's valid until kms_done is called,
        // which can't happen without ending 'scope.
        unsafe {
            let bin = Binary::new();
            if !sys::mongocrypt_kms_ctx_message(self.inner, *bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()
        }
    }

    /// Get the hostname from which to connect over TLS.
    ///
    /// The endpoint consists of a hostname and port separated by a colon.
    /// E.g. "example.com:123". A port is always present.
    pub fn endpoint(&self) -> Result<&'scope str> {
        let mut ptr: *const ::std::os::raw::c_char = ptr::null();
        unsafe {
            if !sys::mongocrypt_kms_ctx_endpoint(
                self.inner,
                &mut ptr as *mut *const ::std::os::raw::c_char,
            ) {
                return Err(self.status().as_error());
            }
            Ok(CStr::from_ptr(ptr).to_str()?)
        }
    }

    /// Indicates how many bytes to feed into `feed`.
    pub fn bytes_needed(&self) -> u32 {
        unsafe { sys::mongocrypt_kms_ctx_bytes_needed(self.inner) }
    }

    /// Feed bytes from the HTTP response.
    ///
    /// Feeding more bytes than what has been returned in `bytes_needed` is an error.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let bin = BinaryRef::new(bytes);
        unsafe {
            if !sys::mongocrypt_kms_ctx_feed(self.inner, *bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    /// Get the KMS provider identifier associated with this KMS request.
    ///
    /// This is used to conditionally configure TLS connections based on the KMS
    /// request. It is useful for KMIP, which authenticates with a client
    /// certificate.
    pub fn kms_provider(&self) -> Result<KmsProvider> {
        let s = unsafe {
            let ptr = sys::mongocrypt_kms_ctx_get_kms_provider(self.inner, ptr::null_mut());
            CStr::from_ptr(ptr).to_str()?
        };
        Ok(KmsProvider::from_name(s))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsProvider {
    /// The type of KMS provider to use.
    pub provider_type: KmsProviderType,

    /// The name of the KMS provider. This value can be set in order to use multiple KMS providers
    /// of the same type in one KMS provider list. If set, a name must also be set for all other
    /// KMS providers of the same type in a list.
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmsProviderType {
    Aws,
    Azure,
    Gcp,
    Kmip,
    Local,
    Other(String),
}

impl KmsProvider {
    pub fn aws() -> Self {
        Self {
            provider_type: KmsProviderType::Aws,
            name: None,
        }
    }

    pub fn azure() -> Self {
        Self {
            provider_type: KmsProviderType::Azure,
            name: None,
        }
    }

    pub fn gcp() -> Self {
        Self {
            provider_type: KmsProviderType::Gcp,
            name: None,
        }
    }

    pub fn local() -> Self {
        Self {
            provider_type: KmsProviderType::Local,
            name: None
        }
    }

    pub fn other(other: impl Into<String>) -> Self {
        Self {
            provider_type: KmsProviderType::Other(other.into()),
            name: None,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn name(&self) -> String {
        let mut full_name = match self.provider_type {
            KmsProviderType::Aws => "aws",
            KmsProviderType::Azure => "azure",
            KmsProviderType::Gcp => "gcp",
            KmsProviderType::Local => "local",
            KmsProviderType::Kmip => "kmip",
            KmsProviderType::Other(ref other) => other,
        }.to_string();
        if let Some(ref name) = self.name {
            full_name.push(':');
            full_name.push_str(name);
        }
        full_name
    }

    pub fn from_name(name: &str) -> Self {
        let (provider_type, name) = match name.split_once(':') {
            Some((provider_type, name)) => {
                (provider_type, Some(name.to_string()))
            }
            None => (name, None),
        };
        let provider_type = match provider_type {
            "aws" => KmsProviderType::Aws,
            "azure" => KmsProviderType::Azure,
            "gcp" => KmsProviderType::Gcp,
            "kmip" => KmsProviderType::Kmip,
            "local" => KmsProviderType::Local,
            other => KmsProviderType::Other(other.to_string()),
        };
        Self {
            provider_type,
            name
        }
    }
}

impl Serialize for KmsProvider {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for KmsProvider {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = KmsProvider;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a string containing a KMS provider name")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(KmsProvider::from_name(v))
            }
        }
        deserializer.deserialize_str(V)
    }
}
