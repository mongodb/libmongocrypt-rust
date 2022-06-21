use std::{
    ffi::CStr,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe, UnwindSafe}, borrow::Borrow,
};

use crate::{
    convert::{binary_bytes, binary_bytes_mut},
    error::{self, HasStatus, Result, Status},
    CryptBuilder,
};

use mongocrypt_sys as sys;

impl CryptBuilder {
    /// Set a handler to get called on every log message.
    pub fn log_handler<F>(mut self, handler: F) -> Result<Self>
    where
        F: Fn(LogLevel, &str) + 'static + UnwindSafe,
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
            if !sys::mongocrypt_setopt_log_handler(*self.inner.borrow(), Some(log_shim), handler_ptr) {
                return Err(self.status().as_error());
            }
        }

        // Now that the handler's successfully set, store it so it gets cleaned up on drop.
        self.cleanup.push(handler);
        Ok(self)
    }

    /// Set crypto hooks.
    ///
    /// * `aes_256_cbc_encrypt` - A `crypto fn`.
    /// * `aes_256_cbc_decrypt` - A `crypto fn`.
    /// * `random` - A `random fn`.
    /// * `hmac_sha_512` - A `hmac fn`.
    /// * `hmac_sha_256` - A `hmac fn`.
    /// * `sha_256` - A `hash fn`.
    ///
    /// The `Fn` bounds used here fall into four distinct kinds, some of which are reused elswhere:
    /// * `crypto fn` - A crypto AES-256-CBC encrypt or decrypt function.
    ///   - `key` - An encryption key (32 bytes for AES_256).
    ///   - `iv` - An initialization vector (16 bytes for AES_256).
    ///   - `in` - The input.  Note, this is already padded.  Encrypt with padding disabled.
    ///   - `out` - The output.
    /// * `hmac fn` - A crypto signature or HMAC function.
    ///   - `key` - An encryption key (32 bytes for HMAC_SHA512).
    ///   - `in` - The input.
    ///   - `out` - The output.
    /// * `hash fn` - A crypto hash (SHA-256) function.
    ///   - `in` - The input.
    ///   - `out` - The output.
    /// * `random fn` - A crypto secure random function.
    ///   - `out` - The output.
    ///   - `count` - The number of random bytes requested.
    pub fn crypto_hooks(
        mut self,
        aes_256_cbc_encrypt: impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
        aes_256_cbc_decrypt: impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
        random: impl Fn(&mut dyn Write, u32) -> Result<()> + UnwindSafe + 'static,
        hmac_sha_512: impl Fn(&[u8], &[u8], &mut dyn Write) -> Result<()> + UnwindSafe + 'static,
        hmac_sha_256: impl Fn(&[u8], &[u8], &mut dyn Write) -> Result<()> + UnwindSafe + 'static,
        sha_256: impl Fn(&[u8], &mut dyn Write) -> Result<()> + UnwindSafe + 'static,
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
                *self.inner.borrow(),
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

    /// Set a crypto hook for the AES256-CTR operations.
    ///
    /// * `aes_256_ctr_encrypt` - A `crypto fn`.  The crypto callback function for encrypt
    /// operation.
    /// * `aes_256_ctr_decrypt` - A `crypto fn`.  The crypto callback function for decrypt
    /// operation.
    pub fn aes_256_ctr(
        mut self,
        aes_256_ctr_encrypt: impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
        aes_256_ctr_decrypt: impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
    ) -> Result<Self> {
        struct Hooks {
            aes_256_ctr_encrypt: CryptoFn,
            aes_256_ctr_decrypt: CryptoFn,
        }
        let hooks = Box::new(Hooks {
            aes_256_ctr_encrypt: Box::new(aes_256_ctr_encrypt),
            aes_256_ctr_decrypt: Box::new(aes_256_ctr_decrypt),
        });
        extern "C" fn aes_256_ctr_encrypt_shim(
            ctx: *mut ::std::os::raw::c_void,
            key: *mut sys::mongocrypt_binary_t,
            iv: *mut sys::mongocrypt_binary_t,
            in_: *mut sys::mongocrypt_binary_t,
            out: *mut sys::mongocrypt_binary_t,
            bytes_written: *mut u32,
            status: *mut sys::mongocrypt_status_t,
        ) -> bool {
            let hooks = unsafe { &*(ctx as *const Hooks) };
            crypto_fn_shim(
                &hooks.aes_256_ctr_encrypt,
                key,
                iv,
                in_,
                out,
                bytes_written,
                status,
            )
        }
        extern "C" fn aes_256_ctr_decrypt_shim(
            ctx: *mut ::std::os::raw::c_void,
            key: *mut sys::mongocrypt_binary_t,
            iv: *mut sys::mongocrypt_binary_t,
            in_: *mut sys::mongocrypt_binary_t,
            out: *mut sys::mongocrypt_binary_t,
            bytes_written: *mut u32,
            status: *mut sys::mongocrypt_status_t,
        ) -> bool {
            let hooks = unsafe { &*(ctx as *const Hooks) };
            crypto_fn_shim(
                &hooks.aes_256_ctr_decrypt,
                key,
                iv,
                in_,
                out,
                bytes_written,
                status,
            )
        }
        unsafe {
            if !sys::mongocrypt_setopt_aes_256_ctr(
                *self.inner.borrow(),
                Some(aes_256_ctr_encrypt_shim),
                Some(aes_256_ctr_decrypt_shim),
                &*hooks as *const Hooks as *mut std::ffi::c_void,
            ) {
                return Err(self.status().as_error());
            }
        }
        self.cleanup.push(hooks);
        Ok(self)
    }

    /// Set an AES256-ECB crypto hook for the AES256-CTR operations. If CTR hook was
    /// configured using `aes_256_ctr`, ECB hook will be ignored.
    ///
    /// * `aes_256_ecb_encrypt` - A `crypto fn`.  The crypto callback function for encrypt
    /// operation.
    pub fn aes_256_ecb(
        mut self,
        aes_256_ecb_encrypt: impl Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
    ) -> Result<Self> {
        let hook: Box<CryptoFn> = Box::new(Box::new(aes_256_ecb_encrypt));
        extern "C" fn shim(
            ctx: *mut ::std::os::raw::c_void,
            key: *mut sys::mongocrypt_binary_t,
            iv: *mut sys::mongocrypt_binary_t,
            in_: *mut sys::mongocrypt_binary_t,
            out: *mut sys::mongocrypt_binary_t,
            bytes_written: *mut u32,
            status: *mut sys::mongocrypt_status_t,
        ) -> bool {
            let hook = unsafe { &*(ctx as *const CryptoFn) };
            crypto_fn_shim(hook, key, iv, in_, out, bytes_written, status)
        }
        unsafe {
            if !sys::mongocrypt_setopt_aes_256_ecb(
                *self.inner.borrow(),
                Some(shim),
                &*hook as *const CryptoFn as *mut std::ffi::c_void,
            ) {
                return Err(self.status().as_error());
            }
        }
        self.cleanup.push(hook);
        Ok(self)
    }

    /// Set a crypto hook for the RSASSA-PKCS1-v1_5 algorithm with a SHA-256 hash.
    ///
    /// See: https://tools.ietf.org/html/rfc3447#section-8.2
    ///
    /// * `sign_rsaes_pkcs1_v1_5` - A `hmac fn`.  The crypto callback function.
    pub fn crypto_hook_sign_rsassa_pkcs1_v1_5(
        mut self,
        sign_rsaes_pkcs1_v1_5: impl Fn(&[u8], &[u8], &mut dyn Write) -> Result<()>
            + UnwindSafe
            + 'static,
    ) -> Result<Self> {
        let hook: Box<HmacFn> = Box::new(Box::new(sign_rsaes_pkcs1_v1_5));
        extern "C" fn shim(
            ctx: *mut ::std::os::raw::c_void,
            key: *mut sys::mongocrypt_binary_t,
            in_: *mut sys::mongocrypt_binary_t,
            out: *mut sys::mongocrypt_binary_t,
            status: *mut sys::mongocrypt_status_t,
        ) -> bool {
            let hook = unsafe { &*(ctx as *const HmacFn) };
            hmac_fn_shim(hook, key, in_, out, status)
        }
        unsafe {
            if !sys::mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(
                *self.inner.borrow(),
                Some(shim),
                &*hook as *const HmacFn as *mut std::ffi::c_void,
            ) {
                return Err(self.status().as_error());
            }
        }
        self.cleanup.push(hook);
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
            }),
        }
    }
}

fn run_hook(hook: impl FnOnce() -> Result<()> + UnwindSafe) -> Result<()> {
    catch_unwind(hook)
        .map_err(|_| error::internal!("panic in rust hook"))?
        .map_err(Into::into)
}

type CryptoFn = Box<dyn Fn(&[u8], &[u8], &[u8], &mut dyn Write) -> Result<()> + UnwindSafe>;
type RandomFn = Box<dyn Fn(&mut dyn Write, u32) -> Result<()> + UnwindSafe>;
type HmacFn = Box<dyn Fn(&[u8], &[u8], &mut dyn Write) -> Result<()> + UnwindSafe>;
type HashFn = Box<dyn Fn(&[u8], &mut dyn Write) -> Result<()> + UnwindSafe>;

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
        let result = run_hook(AssertUnwindSafe(|| {
            hook_fn(key_bytes, iv_bytes, in_bytes, out_bytes_writer)
        }));
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
        Err(e) => e,
    };
    let mut status = Status::from_native(c_status);
    if let Err(status_err) = status.set(&err) {
        eprintln!(
            "Failed to record error:\noriginal error = {:?}\nstatus error = {:?}",
            err, status_err
        );
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
        run_hook(AssertUnwindSafe(|| {
            hook_fn(key_bytes, in_bytes, out_writer)
        }))
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
