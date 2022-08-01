use std::{
    borrow::Borrow,
    ffi::{c_void, CStr},
    marker::PhantomData,
    ptr,
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
};

use bson::{rawdoc, Document, RawDocument};
use mongocrypt_sys as sys;

use crate::{
    binary::{Binary, BinaryBuf, BinaryRef},
    convert::{doc_binary, rawdoc_view, str_bytes_len},
    error::{self, Error, HasStatus, Result},
    native::OwnedPtr,
    Crypt,
};

pub struct CtxBuilder {
    inner: *mut sys::mongocrypt_ctx_t,
}

impl HasStatus for CtxBuilder {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(*self.inner.borrow(), status);
    }
}

impl CtxBuilder {
    /// Does not take ownership of the given pointer.
    pub(crate) fn borrow(inner: *mut sys::mongocrypt_ctx_t) -> Self {
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
            if !sys::mongocrypt_ctx_setopt_key_id(self.inner, *bin.native()) {
                return Err(self.error());
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
            if !sys::mongocrypt_ctx_setopt_key_alt_name(self.inner, *bin.native()) {
                return Err(self.error());
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
            if !sys::mongocrypt_ctx_setopt_key_material(self.inner, *bin.native()) {
                return Err(self.error());
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
                return Err(self.error());
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
                self.inner,
                region_bytes,
                region_len,
                cmk_bytes,
                cmk_len,
            ) {
                return Err(self.error());
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
            if !sys::mongocrypt_ctx_setopt_masterkey_aws_endpoint(self.inner, bytes, len) {
                return Err(self.error());
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
            if !sys::mongocrypt_ctx_setopt_key_encryption_key(self.inner, *bin.native()) {
                return Err(self.error());
            }
            Ok(self)
        }
    }

    /// Set the contention factor used for explicit encryption.
    /// The contention factor is only used for indexed Queryable Encryption.
    pub fn contention_factor(self, contention_factor: i64) -> Result<Self> {
        unsafe {
            if !sys::mongocrypt_ctx_setopt_contention_factor(self.inner, contention_factor) {
                return Err(self.error());
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
            if !sys::mongocrypt_ctx_setopt_index_key_id(self.inner, *bin.native()) {
                return Err(self.error());
            }
        }
        Ok(self)
    }

    /// Set the query type to use for explicit Queryable Encryption.
    pub fn query_type(self, query_type: &str) -> Result<Self> {
        let (s, len) = str_bytes_len(query_type)?;
        unsafe {
            if !sys::mongocrypt_ctx_setopt_query_type(self.inner, s, len) {
                return Err(self.error());
            }
        }
        Ok(self)
    }

    /// Initialize a context to create a data key.
    pub fn build_datakey(self) -> Result<BuiltCtx> {
        unsafe {
            if !sys::mongocrypt_ctx_datakey_init(*self.inner.borrow()) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
    }

    /// Initialize a context for encryption.
    ///
    /// * `db` - The database name.
    /// * `cmd` - The BSON command to be encrypted.
    pub fn build_encrypt(self, db: &str, cmd: &RawDocument) -> Result<BuiltCtx> {
        let (db_bytes, db_len) = str_bytes_len(db)?;
        let cmd_bin = BinaryRef::new(cmd.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_encrypt_init(
                *self.inner.borrow(),
                db_bytes,
                db_len,
                *cmd_bin.native(),
            ) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
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
    pub fn build_explicit_encrypt(self, value: bson::RawBson) -> Result<BuiltCtx> {
        let mut bin: BinaryBuf = rawdoc! { "v": value }.into();
        unsafe {
            if !sys::mongocrypt_ctx_explicit_encrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
    }

    /// Initialize a context for decryption.
    ///
    /// * `doc` - The document to be decrypted.
    pub fn build_decrypt(self, doc: &RawDocument) -> Result<BuiltCtx> {
        let bin = BinaryRef::new(doc.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_decrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
    }

    /// Explicit helper method to decrypt a single BSON object.
    ///
    /// * `msg` - the encrypted BSON.
    pub fn build_explicit_decrypt(self, msg: &[u8]) -> Result<BuiltCtx> {
        let bson_bin = bson::Binary {
            subtype: bson::spec::BinarySubtype::Encrypted,
            bytes: msg.into(),
        };
        let mut bin: BinaryBuf = rawdoc! { "v": bson_bin }.into();
        unsafe {
            if !sys::mongocrypt_ctx_explicit_decrypt_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
    }

    /// Initialize a context to rewrap datakeys.
    ///
    /// * `filter` - The filter to use for the find command on the key vault
    /// collection to retrieve datakeys to rewrap.
    pub fn build_rewrap_many_datakey(self, filter: &RawDocument) -> Result<BuiltCtx> {
        let bin = BinaryRef::new(filter.as_bytes());
        unsafe {
            if !sys::mongocrypt_ctx_rewrap_many_datakey_init(*self.inner.borrow(), *bin.native()) {
                return Err(self.error());
            }
        }
        Ok(BuiltCtx::new())
    }

    #[cfg(test)]
    pub fn build_noop(self) -> Result<BuiltCtx> {
        Ok(BuiltCtx::new())
    }
}

pub struct BuiltCtx {
    _private: (),
}

impl BuiltCtx {
    fn new() -> Self {
        Self { _private: () }
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

pub struct Ctx {
    worker: Mutex<Sender<CtxAction>>,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let (send, recv) = oneshot();
        if self
            .worker
            .lock()
            .unwrap()
            .send(CtxAction::Done(send))
            .is_ok()
        {
            let _ = recv.recv();
        }
    }
}

fn spawn(f: impl FnOnce() + Send + 'static) {
    #[cfg(all(feature = "tokio", feature = "async-std"))]
    {
        compile_error!("'tokio' and 'async-std' cannot both be enabled");
    }
    #[cfg(not(any(feature = "tokio", feature = "async-std")))]
    {
        std::thread::spawn(f);
    }
    #[cfg(feature = "tokio")]
    {
        tokio::task::spawn_blocking(f);
    }
    #[cfg(feature = "async-std")]
    {
        async_std::task::spawn_blocking(f);
    }
}

/// Manages the state machine for encryption or decryption.
impl Ctx {
    pub(crate) fn build(
        crypt: &Crypt,
        f: impl FnOnce(CtxBuilder) -> Result<BuiltCtx> + Send + 'static,
    ) -> Result<Ctx> {
        let crypt_ptr = AssertSendPtr::new(*crypt.inner.borrow());
        //let crypt = ();
        let (send, recv) = mpsc::channel::<CtxAction>();
        spawn(move || Self::worker_loop(crypt_ptr, recv));
        let ctx = Ctx {
            worker: Mutex::new(send),
        };
        ctx.run(|local| {
            let builder = CtxBuilder::borrow(local.0);
            f(builder)
        })??;
        Ok(ctx)
    }

    fn worker_loop(crypt: AssertSendPtr<sys::mongocrypt_t>, actions: Receiver<CtxAction>) {
        let ctx = OwnedPtr::steal(
            unsafe { sys::mongocrypt_ctx_new(crypt.get()) },
            sys::mongocrypt_ctx_destroy,
        );
        while let Ok(action) = actions.recv() {
            match action {
                CtxAction::Fn(f) => f(*ctx.borrow()),
                CtxAction::Done(send) => {
                    let _ = send.send(());
                    return;
                }
            }
        }
    }

    fn run<T: 'static + Send>(&self, f: impl FnOnce(LocalCtx) -> T + Send + 'static) -> Result<T> {
        let (send, recv) = oneshot();
        self.worker
            .lock()
            .unwrap()
            .send(CtxAction::Fn(Box::new(|ctx_ptr| {
                // If the receiver is closed, what happens here doesn't matter.
                let _ = send.send(f(LocalCtx(ctx_ptr)));
            })))
            .map_err(thread_err)?;
        recv.recv().map_err(thread_err)
    }

    /// Convenience wrapper for `run` that turns a boolean failure into a `Result`.
    fn run_result(&self, f: impl FnOnce(&LocalCtx) -> bool + Send + 'static) -> Result<()> {
        self.run(move |local| {
            if !f(&local) {
                return Err(local.error());
            }
            Ok(())
        })?
    }

    /// Get the current state of a context.
    pub fn state(&self) -> Result<State> {
        self.run(|local| {
            let s = unsafe { sys::mongocrypt_ctx_state(local.0) };
            if s == sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_ERROR {
                return Err(local.error());
            }
            Ok(State::from_native(s))
        })?
    }

    /// Get BSON necessary to run the mongo operation when in `State::NeedMongo*` states.
    ///
    /// The returned value:
    /// * for `State::NeedMongoCollinfo` it is a listCollections filter.
    /// * for `State::NeedMongoKeys` it is a find filter.
    /// * for `State::NeedMongoMarkings` it is a command to send to mongocryptd.
    pub fn mongo_op(&self) -> Result<&RawDocument> {
        let op_bytes = {
            let bin = Binary::new();
            let bin_ptr = AssertSendPtr::new(*bin.native());
            self.run_result(move |local| unsafe {
                sys::mongocrypt_ctx_mongo_op(local.0, bin_ptr.get())
            })?;
            // Safety: `mongocrypt_ctx_mongo_op` updates the passed-in `Binary` to point to a chunk of
            // BSON with the same lifetime as the underlying `Ctx`.  The `Binary` itself does not own
            // the memory, and gets cleaned up at the end of the unsafe block.  Lifetime inference on
            // the return type binds `op_bytes` to the same lifetime as `&self`, which is the correct
            // one.
            unsafe { bin.bytes()? }
        };
        rawdoc_view(op_bytes)
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
        let bin_ptr = AssertSendPtr::new(unsafe { *bin.native() });
        self.run_result(move |local| unsafe { sys::mongocrypt_ctx_mongo_feed(local.0, bin_ptr.get()) })
    }

    /// Call when done feeding the reply (or replies) back to the context.
    pub fn mongo_done(&mut self) -> Result<()> {
        self.run_result(|local| unsafe { sys::mongocrypt_ctx_mongo_done(local.0) })
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
        let bin_ptr = AssertSendPtr::new(unsafe { *bin.native() });
        self.run_result(move |local| unsafe {
            sys::mongocrypt_ctx_provide_kms_providers(local.0, bin_ptr.get())
        })
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
        let bytes = {
            let bin = Binary::new();
            let bin_ptr = AssertSendPtr::new(*bin.native());
            self.run_result(move |local| unsafe {
                sys::mongocrypt_ctx_finalize(local.0, bin_ptr.get())
            })?;
            unsafe { bin.bytes()? }
        };
        rawdoc_view(bytes)
    }
}

struct LocalCtx(*mut sys::mongocrypt_ctx_t);

impl HasStatus for LocalCtx {
    unsafe fn native_status(&self, status: *mut sys::mongocrypt_status_t) {
        sys::mongocrypt_ctx_status(self.0, status);
    }
}

struct AssertSendPtr<T> {
    ptr: *mut c_void,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> AssertSendPtr<T> {
    fn new(p: *mut T) -> Self {
        Self {
            ptr: p as *mut c_void,
            _phantom: PhantomData::default(),
        }
    }

    fn get(&self) -> *mut T {
        self.ptr as *mut T
    }
}

unsafe impl<T> Send for AssertSendPtr<T> {}

enum CtxAction {
    Fn(Box<dyn FnOnce(*mut sys::mongocrypt_ctx_t) + Send>),
    Done(OneshotSender<()>),
}

struct OneshotSender<T>(mpsc::SyncSender<T>);

impl<T> OneshotSender<T> {
    fn send(self, value: T) -> Result<()> {
        self.0.send(value).map_err(thread_err)
    }
}

struct OneshotReceiver<T>(mpsc::Receiver<T>);

impl<T> OneshotReceiver<T> {
    fn recv(self) -> Result<T> {
        self.0.recv().map_err(thread_err)
    }
}

fn thread_err<T>(_: T) -> Error {
    error::internal!("ctx thread unexpectedly terminated")
}

/// This is a sync version of `tokio::sync::oneshot::channel`; sending will never block (and so can be used in async code), receiving will synchronously block until a value is sent.
fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
    let (sender, receiver) = mpsc::sync_channel(1);
    (OneshotSender(sender), OneshotReceiver(receiver))
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
    Other(sys::mongocrypt_ctx_state_t),
}

impl State {
    fn from_native(state: sys::mongocrypt_ctx_state_t) -> Self {
        match state {
            sys::mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO => {
                Self::NeedMongoCollinfo
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

impl<'ctx> KmsScope<'ctx> {
    /// Get the next KMS handle.
    ///
    /// Multiple KMS handles may be retrieved at once. Drivers may do this to fan
    /// out multiple concurrent KMS HTTP requests. Feeding multiple KMS requests
    /// is thread-safe.
    ///
    /// If KMS handles are being handled synchronously, the driver can reuse the same
    /// TLS socket to send HTTP requests and receive responses.
    pub fn next_kms_ctx(&self) -> Result<Option<KmsCtx>> {
        let inner = self
            .ctx
            .run(|inner| AssertSendPtr::new(unsafe { sys::mongocrypt_ctx_next_kms_ctx(inner.0) }))?
            .get();
        if inner.is_null() {
            return Ok(None);
        }
        Ok(Some(KmsCtx {
            inner,
            _marker: PhantomData,
        }))
    }
}

impl<'ctx> Drop for KmsScope<'ctx> {
    fn drop(&mut self) {
        // If this errors, it will show up in the next call to `ctx.status()` (or any other ctx call).
        let _ = self.ctx.run(|inner| unsafe {
            sys::mongocrypt_ctx_kms_done(inner.0);
        });
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
                return Err(self.error());
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
                return Err(self.error());
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
                return Err(self.error());
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
        Ok(match s {
            "aws" => KmsProvider::Aws,
            "azure" => KmsProvider::Azure,
            "gcp" => KmsProvider::Gcp,
            "kmip" => KmsProvider::Kmip,
            _ => KmsProvider::Other(s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsProvider {
    Aws,
    Azure,
    Gcp,
    Kmip,
    Other(&'static str),
}
