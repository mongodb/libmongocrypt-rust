#![allow(dead_code)]

use std::ptr;

use mongocrypt_sys::{mongocrypt_binary_t, mongocrypt_binary_new_from_data, mongocrypt_binary_destroy, mongocrypt_binary_data, mongocrypt_binary_len};

pub(crate) struct Binary {
    bytes: Option<Vec<u8>>,
    binary: *mut mongocrypt_binary_t,
}

impl Binary {
    pub(crate) fn new(mut bytes: Vec<u8>) -> Self {
        let binary = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        Self { bytes: Some(bytes), binary }
    }

    pub(crate) fn native(binary: *mut mongocrypt_binary_t) -> Self {
        assert!(binary != ptr::null_mut());
        Self { bytes: None, binary }
    }

    pub(crate) fn binary(&self) -> *mut mongocrypt_binary_t {
        self.binary
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        unsafe {
            mongocrypt_binary_destroy(self.binary);
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
            let data = mongocrypt_binary_data(self.binary);
            let len = mongocrypt_binary_len(self.binary);
            std::slice::from_raw_parts(data, len as usize)
        }
    }
}

pub(crate) struct BinaryRef<'a> {
    _data: &'a [u8],
    binary: *mut mongocrypt_binary_t,
}

impl<'a> BinaryRef<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let data_ptr = data.as_ptr() as *mut u8;
        let binary = unsafe { mongocrypt_binary_new_from_data(data_ptr, data.len() as u32) };
        Self { _data: data, binary }
    }

    pub(crate) fn binary(&self) -> *mut mongocrypt_binary_t {
        self.binary
    }
}

impl<'a> Drop for BinaryRef<'a> {
    fn drop(&mut self) {
        unsafe {
            mongocrypt_binary_destroy(self.binary);
        }
    }
}