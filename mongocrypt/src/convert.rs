use std::ffi::CString;

use bson::{Document, RawDocument};
use mongocrypt_sys as sys;

use crate::{
    binary::BinaryBuf,
    error::{self, encoding, Result},
};

pub(crate) fn doc_binary(doc: &Document) -> Result<BinaryBuf> {
    let mut bytes = vec![];
    doc.to_writer(&mut bytes)
        .map_err(|e| error::internal!("failure serializing doc: {}", e))?;
    Ok(BinaryBuf::new(bytes))
}

pub(crate) fn path_cstring(path: &std::path::Path) -> Result<CString> {
    let bytes = path_bytes(path)?;
    CString::new(bytes).map_err(|e| encoding!("could not convert path to cstring: {:?}", e))
}

#[cfg(unix)]
fn path_bytes(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::os::unix::prelude::OsStrExt;

    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn path_bytes(path: &std::path::Path) -> Result<Vec<u8>> {
    // This is correct for Windows because libmongocrypt internally converts
    // from utf8 to utf16 on that platform.
    use error::Error;

    let s = path
        .to_str()
        .ok_or_else(|| error::encoding!("could not utf-8 encode path {:?}", path))?;
    Ok(s.as_bytes().to_vec())
}

pub(crate) fn str_bytes_len(s: &str) -> Result<(*const std::ffi::c_char, i32)> {
    Ok((
        s.as_bytes().as_ptr() as *const std::ffi::c_char,
        s.as_bytes().len().try_into()?,
    ))
}

pub(crate) fn rawdoc_view(bytes: &[u8]) -> Result<&RawDocument> {
    RawDocument::from_bytes(bytes).map_err(|e| error::internal!("document parse failure: {}", e))
}

pub(crate) unsafe fn binary_bytes<'a>(binary: *mut sys::mongocrypt_binary_t) -> Result<&'a [u8]> {
    let data = sys::mongocrypt_binary_data(binary);
    let len = sys::mongocrypt_binary_len(binary);
    Ok(std::slice::from_raw_parts(data, len.try_into()?))
}

pub(crate) unsafe fn binary_bytes_mut<'a>(
    binary: *mut sys::mongocrypt_binary_t,
) -> Result<&'a mut [u8]> {
    let data = sys::mongocrypt_binary_data(binary);
    let len = sys::mongocrypt_binary_len(binary);
    Ok(std::slice::from_raw_parts_mut(data, len.try_into()?))
}
