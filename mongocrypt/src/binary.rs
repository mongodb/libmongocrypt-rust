use mongocrypt_sys as sys;

pub(crate) struct Binary {
    inner: *mut sys::mongocrypt_binary_t,
}

impl Drop for Binary {
    fn drop(&mut self) {
        unsafe {
            sys::mongocrypt_binary_destroy(self.inner);
        }
    }
}

impl Binary {
    pub(crate) fn new() -> Self {
        Self {
            inner: unsafe { sys::mongocrypt_binary_new() },
        }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_binary_t {
        self.inner
    }

    pub(crate) unsafe fn bytes<'a>(&self) -> &'a [u8] {
        let data = sys::mongocrypt_binary_data(self.inner);
        let len = sys::mongocrypt_binary_len(self.inner);
        std::slice::from_raw_parts(data, len as usize)
    }
}

pub(crate) struct BinaryBuf {
    _bytes: Vec<u8>,
    inner: Binary,
}

impl BinaryBuf {
    pub(crate) fn new(mut bytes: Vec<u8>) -> Self {
        let native = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            sys::mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        Self {
            _bytes: bytes,
            inner: Binary { inner: native },
        }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_binary_t {
        self.inner.inner
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
            inner: Binary { inner: native },
        }
    }

    pub(crate) fn native(&self) -> *mut sys::mongocrypt_binary_t {
        self.inner.inner
    }
}