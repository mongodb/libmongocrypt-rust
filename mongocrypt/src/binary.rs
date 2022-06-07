use std::ptr;

use mongocrypt_sys as sys;

pub(crate) struct Binary {
    bytes: Option<Vec<u8>>,
    inner: *mut sys::mongocrypt_binary_t,
}

#[allow(dead_code)]
impl Binary {
    pub(crate) fn new(mut bytes: Vec<u8>) -> Self {
        let binary = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            sys::mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        Self { bytes: Some(bytes), inner: binary }
    }

    pub(crate) fn from_native(binary: *mut sys::mongocrypt_binary_t) -> Self {
        assert!(binary != ptr::null_mut());
        Self { bytes: None, inner: binary }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_binary_t {
        self.inner
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        unsafe {
            sys::mongocrypt_binary_destroy(self.inner);
        }
    }
}

impl std::ops::Deref for Binary {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        if let Some(bytes) = &self.bytes {
            return &bytes;
        }
        unsafe {
            let data = sys::mongocrypt_binary_data(self.inner);
            let len = sys::mongocrypt_binary_len(self.inner);
            std::slice::from_raw_parts(data, len as usize)
        }
    }
}

pub(crate) struct BinaryRef<'a> {
    _data: &'a [u8],
    inner: *mut sys::mongocrypt_binary_t,
}

impl<'a> BinaryRef<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let data_ptr = data.as_ptr() as *mut u8;
        let inner = unsafe { sys::mongocrypt_binary_new_from_data(data_ptr, data.len() as u32) };
        Self { _data: data, inner }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_binary_t {
        self.inner
    }
}

impl<'a> Drop for BinaryRef<'a> {
    fn drop(&mut self) {
        unsafe {
            sys::mongocrypt_binary_destroy(self.inner);
        }
    }
}