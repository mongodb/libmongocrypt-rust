mod example_state_machine;

use std::{ffi::CStr, ptr};

use super::*;

#[test]
fn version_is_utf8() {
    let c_version = unsafe {
        CStr::from_ptr(mongocrypt_version(ptr::null_mut()))
    };
    let version = c_version.to_str();
    assert!(version.is_ok(), "{}", version.unwrap_err());
}

#[test]
fn binary_empty() {
    unsafe {
        let bin = mongocrypt_binary_new();
        assert_eq!(ptr::null_mut(), mongocrypt_binary_data(bin));
        mongocrypt_binary_destroy(bin);
    }
}

#[test]
fn binary_roundtrip() {
    let mut data = [1, 2, 3];
    unsafe {
        let data_ptr = data.as_mut_ptr() as *mut u8;
        let bin = mongocrypt_binary_new_from_data(data_ptr, data.len() as u32);
        assert_eq!(mongocrypt_binary_data(bin), data_ptr);
        assert_eq!(mongocrypt_binary_len(bin), data.len() as u32);
        mongocrypt_binary_destroy(bin);
    }
}

fn cs(bytes: &[u8]) -> &CStr {
    CStr::from_bytes_with_nul(bytes).unwrap()
}

#[test]
fn status_roundtrip() {
    let message = cs(b"hello mongocryptd\0");
    unsafe {
        let status = mongocrypt_status_new();
        mongocrypt_status_set(
            status,
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
            42,
            message.as_ptr(),
            -1
        );
        assert_eq!(
            mongocrypt_status_type(status),
            mongocrypt_status_type_t_MONGOCRYPT_STATUS_ERROR_CLIENT,
        );
        assert_eq!(
            mongocrypt_status_code(status),
            42,
        );
        assert_eq!(
            CStr::from_ptr(mongocrypt_status_message(status, ptr::null_mut())),
            message,
        );
        mongocrypt_status_destroy(status);
    }
}

#[test]
fn crypt_setopt() {
    unsafe {
        let crypt = mongocrypt_new();

        unsafe extern "C" fn log_cb(
            _level: mongocrypt_log_level_t,
            _message: *const ::std::os::raw::c_char,
            _message_len: u32,
            _ctx: *mut ::std::os::raw::c_void,        
        ) {}
        assert!(mongocrypt_setopt_log_handler(crypt, Some(log_cb), ptr::null_mut()));

        let mut doc_bytes = bson::rawdoc! {}.into_bytes();
        let doc_bin = mongocrypt_binary_new_from_data(doc_bytes.as_mut_ptr(), doc_bytes.len() as u32);

        assert!(mongocrypt_setopt_kms_providers(crypt, doc_bin));
        assert!(mongocrypt_setopt_schema_map(crypt, doc_bin));
        assert!(mongocrypt_setopt_encrypted_field_config_map(crypt, doc_bin));

        mongocrypt_binary_destroy(doc_bin);
        drop(doc_bytes);  // enforce lifespan longer than `doc_bin`

        mongocrypt_setopt_append_csfle_search_path(
            crypt,
            cs(b"$SYSTEM\0").as_ptr(),
        );
        mongocrypt_setopt_set_csfle_lib_path_override(
            crypt,
            cs(b"$ORIGIN\0").as_ptr(),
        );
        mongocrypt_setopt_use_need_kms_credentials_state(crypt);

        mongocrypt_destroy(crypt);
    }
}

unsafe fn crypt_stub_setopt(crypt: *mut mongocrypt_t) {
    assert!(mongocrypt_setopt_kms_provider_aws(
        crypt,
        cs(b"example\0").as_ptr(),
        -1,
        cs(b"example\0").as_ptr(),
        -1,
    ));
}

#[test]
fn crypt_lifecycle() {
    unsafe {
        let crypt = mongocrypt_new();
        crypt_stub_setopt(crypt);
        assert!(mongocrypt_init(crypt));

        let status = mongocrypt_status_new();
        assert!(mongocrypt_status(crypt, status));
        assert!(mongocrypt_status_ok(status));
        mongocrypt_status_destroy(status);

        mongocrypt_destroy(crypt);
    }
}

#[test]
fn crypt_csfle_version() {
    unsafe {
        let crypt = mongocrypt_new();
        crypt_stub_setopt(crypt);
        assert!(mongocrypt_init(crypt));

        assert_eq!(ptr::null(), mongocrypt_csfle_version_string(crypt, ptr::null_mut()));
        assert_eq!(0, mongocrypt_csfle_version(crypt));

        mongocrypt_destroy(crypt);
    }
}

#[test]
fn ctx_lifecycle() {
    unsafe {
        let crypt = mongocrypt_new();
        crypt_stub_setopt(crypt);
        assert!(mongocrypt_init(crypt));

        let ctx = mongocrypt_ctx_new(crypt);
        let status = mongocrypt_status_new();
        assert!(mongocrypt_ctx_status(ctx, status));
        assert!(mongocrypt_status_ok(status));

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}