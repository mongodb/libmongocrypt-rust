use std::ffi::CStr;

use mongocrypt_sys as sys;

use crate::error::{ErrorKind, Status};

#[test]
fn status_parse() {
    let status = Status::new();
    let message = CStr::from_bytes_with_nul(b"hello mongocryptd\0").unwrap();
    unsafe {
        sys::mongocrypt_status_set(
            status.native(),
            sys::mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
            42,
            message.as_ptr(),
            -1,
        );
    }
    let err = status.check().unwrap_err();
    assert_eq!(ErrorKind::Client, err.kind);
    assert_eq!(42, err.code);
    assert_eq!("hello mongocryptd", err.message.unwrap());
}
