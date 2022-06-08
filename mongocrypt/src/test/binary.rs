use mongocrypt_sys as sys;

use crate::binary::{BinaryBuf, BinaryRef};

#[test]
fn binary_owned_roundtrip() {
    let data = vec![1, 2, 3];
    let bin = BinaryBuf::new(data.clone());
    let bin_slice = unsafe {
        let data = sys::mongocrypt_binary_data(bin.native());
        let len = sys::mongocrypt_binary_len(bin.native());
        std::slice::from_raw_parts(data, len as usize)
    };
    assert_eq!(&data, bin_slice);
}

#[test]
fn binary_ref_roundtrip() {
    let data = [1, 2, 3];
    let bin = BinaryRef::new(&data);
    let bin_slice = unsafe {
        let data = sys::mongocrypt_binary_data(bin.native());
        let len = sys::mongocrypt_binary_len(bin.native());
        std::slice::from_raw_parts(data, len as usize)
    };
    assert_eq!(&data, bin_slice);
}