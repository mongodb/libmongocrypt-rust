use bson::Document;

use crate::{error::{Result, self}, binary::BinaryBuf};

pub(crate) fn doc_binary(doc: &Document) -> Result<BinaryBuf> {
    let mut bytes = vec![];
    doc.to_writer(&mut bytes).map_err(|e| error::internal!("failure serializing doc: {}", e))?;
    Ok(BinaryBuf::new(bytes))
}

#[cfg(unix)]
pub(crate) fn path_bytes(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::{os::unix::prelude::OsStrExt};

    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
pub(crate) fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    // This is correct for Windows because libmongocrypt internally converts
    // from utf8 to utf16 on that platform.
    use error::Error;

    let s = path.to_str().ok_or_else(|| Error {
        kind: ErrorKind::Encoding,
        code: 0,
        message: Some(format!("could not utf-8 encode path {:?}", path)),
    })?;
    Ok(s.as_bytes().to_vec())
}

pub(crate) fn str_bytes_len(s: &str) -> Result<(*const i8, i32)> {
    Ok((
        s.as_bytes().as_ptr() as *const i8,
        s.as_bytes().len().try_into().map_err(|e| error::internal!("size overflow: {}", e))?
    ))
}