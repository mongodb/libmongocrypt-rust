use std::borrow::Borrow;

use bson::RawDocumentBuf;
use mongocrypt_sys as sys;

use crate::convert::binary_bytes;
use crate::error::Result;
use crate::native::OwnedPtr;

pub(crate) struct Binary {
    inner: OwnedPtr<sys::mongocrypt_binary_t>,
}

impl Binary {
    pub(crate) fn new() -> Self {
        Self {
            inner: OwnedPtr::steal(
                unsafe { sys::mongocrypt_binary_new() },
                sys::mongocrypt_binary_destroy,
            ),
        }
    }

    /// Takes ownership of the given pointer, and will destroy it on drop.
    fn steal(inner: *mut sys::mongocrypt_binary_t) -> Self {
        Self {
            inner: OwnedPtr::steal(inner, sys::mongocrypt_binary_destroy),
        }
    }

    pub(crate) fn native(&self) -> &*mut sys::mongocrypt_binary_t {
        self.inner.borrow()
    }

    /// This is unsafe because the lifetime of the returned slice is unbound and determined by the caller, not linked to the lifetime of `self`.
    pub(crate) unsafe fn bytes<'a>(&self) -> Result<&'a [u8]> {
        binary_bytes(*self.inner.borrow())
    }
}

pub(crate) struct BinaryBuf {
    _bytes: Box<[u8]>,
    inner: Binary,
}

impl BinaryBuf {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let mut bytes = bytes.into_boxed_slice();
        let native = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            sys::mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        Self {
            _bytes: bytes,
            inner: Binary::steal(native),
        }
    }

    pub(crate) fn native(&mut self) -> &*mut sys::mongocrypt_binary_t {
        self.inner.native()
    }
}

impl From<RawDocumentBuf> for BinaryBuf {
    fn from(raw: RawDocumentBuf) -> Self {
        BinaryBuf::new(raw.into_bytes())
    }
}

pub(crate) struct BinaryRef<'a> {
    _data: &'a [u8],
    inner: Binary,
}

impl<'a> BinaryRef<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let data_ptr = data.as_ptr() as *mut u8;
        let native = unsafe { sys::mongocrypt_binary_new_from_data(data_ptr, data.len() as u32) };
        Self {
            _data: data,
            inner: Binary::steal(native),
        }
    }

    pub(crate) fn native(&self) -> &*mut sys::mongocrypt_binary_t {
        self.inner.native()
    }
}
