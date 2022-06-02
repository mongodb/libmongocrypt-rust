use std::ops::Deref;

use crate::binary::Binary;

#[test]
fn binary_owned_roundtrip() {
    let data = vec![1, 2, 3];
    let bin = Binary::new(data.clone());
    assert_eq!(data.deref(), bin.deref());
}