use std::{ffi::CStr, marker::PhantomData, ptr};

use bson::{doc, Document, RawDocument};
use mongocrypt_sys as sys;

use crate::{
    binary::{Binary, BinaryRef},
    convert::{doc_binary, rawdoc, str_bytes_len},
    error::{self, HasStatus, Result},
};

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
            if !sys::mongocrypt_ctx_setopt_key_id(self.inner, bin.native()) {
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
        let bin = doc_binary(&doc! { "keyAltName": key_alt_name })?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_alt_name(self.inner, bin.native()) {
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
        let bin = doc_binary(&doc! { "keyMaterial": bson_bin })?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_material(self.inner, bin.native()) {
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
            if !sys::mongocrypt_ctx_setopt_algorithm(self.inner, algorithm.c_str().as_ptr(), -1) {
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

    /// Identify a custom AWS endpoint when creating a data key.
    /// This is used internally to construct the correct HTTP request
    /// (with the Host header set to this endpoint). This endpoint
    /// is persisted in the new data key, and will be returned via
    /// `KmsCtx::endpoint`.
    ///
    /// This has been superseded by the more flexible `key_encryption_key`.
    pub fn masterkey_aws_endpoint(self, endpoint: &str) -> Result<Self> {
        let (bytes, len) = str_bytes_len(endpoint)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_aws_endpoint(self.inner, bytes, len) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    /// Set the master key to "local" for creating a data key.
    /// 
    /// This has been superseded by the more flexible `key_encryption_key`.
    pub fn masterkey_local(self) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_masterkey_local(self.inner) {
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
        let bin = doc_binary(key_encryption_key)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_key_encryption_key(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            Ok(self)
        }
    }

    pub fn index_type(self, index_type: IndexType) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_index_type(self.inner, index_type.as_native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn contention_factor(self, contention_factor: i64) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_contention_factor(self.inner, contention_factor) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn index_key_id(self, key_id: &bson::Uuid) -> Result<Self> {
        let bytes = key_id.bytes();
        let bin = BinaryRef::new(&bytes);
        unsafe {
            if !sys::mongocrypt_ctx_setopt_index_key_id(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    pub fn query_type(self, query_type: QueryType) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_query_type(self.inner, query_type.as_native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(self)
    }

    fn into_ctx(mut self) -> Ctx {
        let out = Ctx { inner: self.inner };
        self.inner = ptr::null_mut();
        out
    }

    /// Initialize a context to create a data key.
    pub fn build_datakey(self) -> Result<Ctx> {
        unsafe {
            if !sys::mongocrypt_ctx_datakey_init(self.inner) {
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
            if !sys::mongocrypt_ctx_encrypt_init(self.inner, db_bytes, db_len, cmd_bin.native()) {
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
    pub fn build_explicit_encrypt(self, value: &bson::Bson) -> Result<Ctx> {
        let bin = doc_binary(&doc! { "v": value })?;
        unsafe {
            if !sys::mongocrypt_ctx_explicit_encrypt_init(self.inner, bin.native()) {
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
            if !sys::mongocrypt_ctx_decrypt_init(self.inner, bin.native()) {
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
        let bin = doc_binary(&doc! { "v": bson_bin })?;
        unsafe {
            if !sys::mongocrypt_ctx_explicit_decrypt_init(self.inner, bin.native()) {
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
        let bin = BinaryRef::new(&filter.as_bytes());
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
            Self::AeadAes256CbcHmacSha512Deterministic => {
                b"AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic\0"
            }
            Self::AeadAes256CbcHmacSha512Random => b"AEAD_AES_256_CBC_HMAC_SHA_512-Random\0",
        };
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum IndexType {
    None,
    Equality,
}

impl IndexType {
    fn as_native(self) -> sys::mongocrypt_index_type_t {
        match self {
            IndexType::None => sys::mongocrypt_index_type_t_MONGOCRYPT_INDEX_TYPE_NONE,
            IndexType::Equality => sys::mongocrypt_index_type_t_MONGOCRYPT_INDEX_TYPE_EQUALITY,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum QueryType {
    Equality,
}

impl QueryType {
    fn as_native(self) -> sys::mongocrypt_query_type_t {
        match self {
            QueryType::Equality => sys::mongocrypt_query_type_t_MONGOCRYPT_QUERY_TYPE_EQUALITY,
        }
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

/// Manages the state machine for encryption or decryption.
impl Ctx {
    /// Get the current state of a context.
    pub fn state(&self) -> Result<State> {
        let s = unsafe { sys::mongocrypt_ctx_state(self.inner) };
        if s == sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_ERROR {
            return Err(self.status().as_error());
        }
        State::from_native(s)
    }

    /// Get BSON necessary to run the mongo operation when in `State::NeedMongo*` states.
    /// 
    /// The returned value:
    /// * for `State::NeedMongoCollinfo` it is a listCollections filter.
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
            if !sys::mongocrypt_ctx_mongo_op(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()?
        };
        rawdoc(op_bytes)
    }

    /// Feed a BSON reply or result when this context is in
    /// `State::NeedMongo*` states. This may be called multiple times
    /// depending on the operation.
    /// 
    /// `reply` is a BSON document result being fed back for this operation.
    /// - For `State::NeedMongoCollinfo` it is a doc from a listCollections
    /// cursor. (Note, if listCollections returned no result, do not call this
    /// function.)
    /// - For `State::NeedMongoKeys` it is a doc from a find cursor.
    ///   (Note, if find returned no results, do not call this function.)
    /// - For `State::NeedMongoMarkings` it is a reply from mongocryptd.
    pub fn mongo_feed(&mut self, reply: &RawDocument) -> Result<()> {
        let bin = BinaryRef::new(reply.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_mongo_feed(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    /// Call when done feeding the reply (or replies) back to the context.
    pub fn mongo_done(&mut self) -> Result<()> {
        unsafe {
            if !sys::mongocrypt_ctx_mongo_done(self.inner) {
                return Err(self.status().as_error());
            }
        }
        Ok(())
    }

    pub fn kms_scope(&mut self) -> KmsScope {
        KmsScope { ctx: self }
    }

    /// all in response to the `State::NeedKmsCredentials` state
    /// to set per-context KMS provider settings. These follow the same format
    /// as `CryptBuilder::kms_providers`. If no keys are present in the
    /// BSON input, the KMS provider settings configured for the `Crypt`
    /// at initialization are used.
    pub fn provide_kms_providers(&mut self, kms_providers_definition: &RawDocument) -> Result<()> {
        let bin = BinaryRef::new(kms_providers_definition.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_provide_kms_providers(self.inner, bin.native()) {
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
            if !sys::mongocrypt_ctx_finalize(self.inner, bin.native()) {
                return Err(self.status().as_error());
            }
            bin.bytes()?
        };
        rawdoc(bytes)
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
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO => {
                Ok(Self::NeedMongoCollinfo)
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_MARKINGS => {
                Ok(Self::NeedMongoMarkings)
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_KEYS => Ok(Self::NeedMongoKeys),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS => Ok(Self::NeedKms),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS => {
                Ok(Self::NeedKmsCredentials)
            }
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_READY => Ok(Self::Ready),
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_DONE => Ok(Self::Done),
            _ => Err(error::internal!("unexpected ctx state {}", state)),
        }
    }
}

/// A scope bounding the processing of (potentially multiple) KMS handles.
pub struct KmsScope<'ctx> {
    ctx: &'ctx Ctx,
}

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
        let inner = unsafe { sys::mongocrypt_ctx_next_kms_ctx(self.ctx.inner) };
        if inner == ptr::null_mut() {
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
            sys::mongocrypt_ctx_kms_done(self.ctx.inner);
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
            if !sys::mongocrypt_kms_ctx_message(self.inner, bin.native()) {
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
            if !sys::mongocrypt_kms_ctx_feed(self.inner, bin.native()) {
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
    /// 
    /// Returns one of the static strings: "aws", "azure", "gcp", or "kmip".
    pub fn get_kms_provider(&self) -> Result<&'static str> {
        unsafe {
            let ptr = sys::mongocrypt_kms_ctx_get_kms_provider(self.inner, ptr::null_mut());
            Ok(CStr::from_ptr(ptr).to_str()?)
        }
    }
}
