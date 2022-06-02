use std::ops::Deref;

use mongocrypt_sys::{mongocrypt_binary_data, mongocrypt_binary_len};

use crate::binary::{Binary, BinaryRef};

#[test]
fn binary_owned_roundtrip() {
    let data = vec![1, 2, 3];
    let bin = Binary::new(data.clone());
    assert_eq!(data.deref(), bin.deref());
}

#[test]
fn binary_ref_roundtrip() {
    let data = [1, 2, 3];
    let bin = BinaryRef::new(&data);
    let bin_slice = unsafe {
        let data = mongocrypt_binary_data(bin.binary());
        let len = mongocrypt_binary_len(bin.binary());
        std::slice::from_raw_parts(data, len as usize)
    };
    assert_eq!(&data, bin_slice);
}