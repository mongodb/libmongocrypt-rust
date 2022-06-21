use std::borrow::Borrow;

pub(crate) type Destroy<T> = unsafe extern "C" fn(*mut T);

pub(crate) struct OwnedPtr<T> {
    inner: *mut T,
    destroy: Destroy<T>,
}

#[cfg(all(test, feature = "compile_fail"))]
#[test]
fn use_after_free() {
    unsafe extern "C" fn destroy(_ptr: *mut ()) {}
    let owned: OwnedPtr<()> = OwnedPtr::new(std::ptr::null_mut(), destroy);
    let ptr = owned.borrow();
    std::mem::drop(owned);
    unsafe { destroy(*ptr) };
}

impl<T> OwnedPtr<T> {
    pub(crate) fn new(inner: *mut T, destroy: Destroy<T>) -> Self {
        Self { inner, destroy }
    }

    pub(crate) fn borrow_const(&self) -> &*const T {
        let borrow: &*mut T = self.borrow();
        let borrow_ptr = borrow as *const *mut T;
        let borrow_const_ptr = borrow_ptr as *const *const T;
        unsafe { &*borrow_const_ptr }
    }
}

impl<T> Borrow<*mut T> for OwnedPtr<T> {
    fn borrow(&self) -> &*mut T {
        &self.inner
    }
}

impl<T> Drop for OwnedPtr<T> {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                (self.destroy)(self.inner);
            }
        }
    }
}
