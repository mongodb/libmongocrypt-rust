use std::{ffi::CStr, panic::{catch_unwind, AssertUnwindSafe, UnwindSafe}, io::Write};

use crate::{CryptBuilder, error::{Result, self, CryptResult, HasStatus, Error, ErrorKind, Status}, convert::{binary_bytes, binary_bytes_mut}};

use mongocrypt_sys as sys;

impl CryptBuilder {
    pub fn log_handler<F>(mut self, handler: F) -> Result<Self>
        where F: Fn(LogLevel, &str) + 'static + UnwindSafe
    {
        type LogCb = dyn Fn(LogLevel, &str) + UnwindSafe;

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
            let _ = run_hook(AssertUnwindSafe(|| {
                handler(level, &message);
                Ok(())
            }));
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

    //pub fn crypto_hooks(mut self, hooks: CryptoHooks) -> Result<Self> {
    pub fn crypto_hooks<
        Aes256CbcEncrypt: Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe + 'static,
        Aes256CbcDecrypt: Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe + 'static,
        Random: Fn(&mut dyn Write, u32) -> CryptResult<()> + UnwindSafe + 'static,
        HmacSha512: Fn(&[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe + 'static,
        HmacSha256: Fn(&[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe + 'static,
        Sha256: Fn(&[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe + 'static,
    >(
        mut self,
        aes_256_cbc_encrypt: Aes256CbcEncrypt,
        aes_256_cbc_decrypt: Aes256CbcDecrypt,
        random: Random,
        hmac_sha_512: HmacSha512,
        hmac_sha_256: HmacSha256,
        sha_256: Sha256,
    ) -> Result<Self> {
        let hooks = Box::new(CryptoHooks {
            aes_256_cbc_encrypt: Box::new(aes_256_cbc_encrypt),
            aes_256_cbc_decrypt: Box::new(aes_256_cbc_decrypt),
            random: Box::new(random),
            hmac_sha_512: Box::new(hmac_sha_512),
            hmac_sha_256: Box::new(hmac_sha_256),
            sha_256: Box::new(sha_256),
        });
        unsafe {
            if !sys::mongocrypt_setopt_crypto_hooks(
                self.inner,
                Some(aes_256_cbc_encrypt_shim),
                Some(aes_256_cbc_decrypt_shim),
                Some(random_shim),
                Some(hmac_sha_512_shim),
                Some(hmac_sha_256_shim),
                Some(sha_256_shim),
                &*hooks as *const CryptoHooks as *mut std::ffi::c_void,
            ) {
                return Err(self.status().as_error());
            }
        }
        self.cleanup.push(hooks);
        Ok(self)
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

fn run_hook(hook: impl FnOnce() -> CryptResult<()> + UnwindSafe) -> Result<()> {
    catch_unwind(hook)
        .map_err(|_| error::internal!("panic in rust hook"))?
        .map_err(Into::into)
}

/// Parameters:
/// * encryption key (32 bytes for AES_256)
/// * initialization vector (16 bytes for AES_256)
/// * the input
/// * destination for output
type CryptoFn = Box<dyn Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe>;
/// Parameters:
/// * destination for output
/// * number of random bytes requested
type RandomFn = Box<dyn Fn(&mut dyn Write, u32) -> CryptResult<()> + UnwindSafe>;
/// Parameters:
/// * encryption key (32 bytes for HMAC_SHA512)
/// * the input
/// * destination for output
type HmacFn = Box<dyn Fn(&[u8], &[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe>;
/// Parameters
/// * the input
/// * destination for output
type HashFn = Box<dyn Fn(&[u8], &mut dyn Write) -> CryptResult<()> + UnwindSafe>;

// This is exposed directly rather than created internal to CryptBuilder::crypto_hooks because
// doing it that way ran into https://github.com/rust-lang/rust/issues/41078.
struct CryptoHooks {
    aes_256_cbc_encrypt: CryptoFn,
    random: RandomFn,
    hmac_sha_512: HmacFn,
    aes_256_cbc_decrypt: CryptoFn,
    hmac_sha_256: HmacFn,
    sha_256: HashFn,
}


fn crypto_fn_shim(
    hook_fn: &CryptoFn,
    key: *mut sys::mongocrypt_binary_t,
    iv: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    bytes_written: *mut u32,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    // Convenience scope for intermediate error propagation via `?`.
    let result = || -> Result<()> {
        let key_bytes = unsafe { binary_bytes(key)? };
        let iv_bytes = unsafe { binary_bytes(iv)? };
        let in_bytes = unsafe { binary_bytes(in_)? };
        let mut out_bytes = unsafe { binary_bytes_mut(out)? };
        let buffer_len = out_bytes.len();
        let out_bytes_writer: &mut dyn Write = &mut out_bytes;
        let result = run_hook(AssertUnwindSafe(|| hook_fn(key_bytes, iv_bytes, in_bytes, out_bytes_writer)));
        let written = buffer_len - out_bytes.len();
        unsafe {
            *bytes_written = written.try_into()?;
        }
        result
    }();
    write_status(result, c_status)
}

fn write_status(result: Result<()>, c_status: *mut sys::mongocrypt_status_t) -> bool {
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
    // The status is owned by the caller, so don't run cleanup.
    std::mem::forget(status);
    false
}

extern "C" fn aes_256_cbc_encrypt_shim(
    ctx: *mut ::std::os::raw::c_void,
    key: *mut sys::mongocrypt_binary_t,
    iv: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    bytes_written: *mut u32,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    let hooks = unsafe { &*(ctx as *const CryptoHooks) };
    crypto_fn_shim(
        &hooks.aes_256_cbc_encrypt,
        key,
        iv,
        in_,
        out,
        bytes_written,
        c_status,
    )
}

extern "C" fn aes_256_cbc_decrypt_shim(
    ctx: *mut ::std::os::raw::c_void,
    key: *mut sys::mongocrypt_binary_t,
    iv: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    bytes_written: *mut u32,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    let hooks = unsafe { &*(ctx as *const CryptoHooks) };
    crypto_fn_shim(
        &hooks.aes_256_cbc_decrypt,
        key,
        iv,
        in_,
        out,
        bytes_written,
        c_status,
    )
}

extern "C" fn random_shim(
    ctx: *mut ::std::os::raw::c_void,
    out: *mut sys::mongocrypt_binary_t,
    count: u32,
    status: *mut sys::mongocrypt_status_t,
) -> bool {
    let result = || -> Result<()> {
        let hooks = unsafe { &*(ctx as *const CryptoHooks) };
        let out_writer: &mut dyn Write = &mut unsafe { binary_bytes_mut(out)? };
        run_hook(AssertUnwindSafe(|| (hooks.random)(out_writer, count)))
    }();
    write_status(result, status)
}

fn hmac_fn_shim(
    hook_fn: &HmacFn,
    key: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    let result = || -> Result<()> {
        let key_bytes = unsafe { binary_bytes(key)? };
        let in_bytes = unsafe { binary_bytes(in_)? };
        let out_writer: &mut dyn Write = &mut unsafe { binary_bytes_mut(out)? };
        run_hook(AssertUnwindSafe(|| hook_fn(key_bytes, in_bytes, out_writer)))
    }();
    write_status(result, c_status)
}

extern "C" fn hmac_sha_512_shim(
    ctx: *mut ::std::os::raw::c_void,
    key: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    let hooks = unsafe { &*(ctx as *const CryptoHooks) };
    hmac_fn_shim(&hooks.hmac_sha_512, key, in_, out, c_status)
}

extern "C" fn hmac_sha_256_shim(
    ctx: *mut ::std::os::raw::c_void,
    key: *mut sys::mongocrypt_binary_t,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    c_status: *mut sys::mongocrypt_status_t,
) -> bool {
    let hooks = unsafe { &*(ctx as *const CryptoHooks) };
    hmac_fn_shim(&hooks.hmac_sha_256, key, in_, out, c_status)
}

extern "C" fn sha_256_shim(
    ctx: *mut ::std::os::raw::c_void,
    in_: *mut sys::mongocrypt_binary_t,
    out: *mut sys::mongocrypt_binary_t,
    status: *mut sys::mongocrypt_status_t,
) -> bool {
    let hooks = unsafe { &*(ctx as *const CryptoHooks) };
    let result = || -> Result<()> {
        let in_bytes = unsafe { binary_bytes(in_)? };
        let out_writer: &mut dyn Write = &mut unsafe { binary_bytes_mut(out)? };
        run_hook(AssertUnwindSafe(|| (hooks.sha_256)(in_bytes, out_writer)))
    }();
    write_status(result, status)
}
