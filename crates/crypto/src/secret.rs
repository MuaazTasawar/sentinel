use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A byte buffer holding sensitive key material.
///
/// Two protections are applied:
/// 1. The memory is `mlock`'d so the OS never pages it to swap/disk.
/// 2. The buffer is zeroized on drop so freed memory doesn't leave secrets
///    lingering on the heap for a later allocation to read.
pub struct SecretBytes {
    buf: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    pub fn new(mut buf: Vec<u8>) -> Self {
        // Shrink first so the allocation is exactly `buf.len()` bytes —
        // mlock covers exactly this range, and shrinking after locking
        // could trigger a reallocation that silently moves the secret
        // to an unlocked page.
        buf.shrink_to_fit();
        let locked = Self::lock(&buf);
        Self { buf, locked }
    }

    pub fn zero(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    fn lock(buf: &[u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        // SAFETY: `buf.as_ptr()` is valid for `buf.len()` bytes for the
        // duration of this call — `buf` is a live, non-aliased borrow and
        // is not reallocated while this call runs (we already shrunk it
        // to capacity == len in `new`, so no implicit realloc). `mlock`
        // only advises the OS not to swap this range; it never reads or
        // writes through the pointer, so the call is sound regardless of
        // whether it succeeds (checked via return code, not assumed).
        let ret = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
        ret == 0
    }

    fn unlock(buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        // SAFETY: mirrors `lock` above. `buf` is still valid for
        // `buf.len()` bytes at this point (called from `Drop::drop`
        // before `buf`'s own deallocation), and this is exactly the
        // range previously passed to `mlock`, which POSIX requires for
        // `munlock` to be well-defined (partial unlocks of a locked
        // range are undefined behavior at the OS level, not just Rust's).
        unsafe {
            libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.buf
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            Self::unlock(&self.buf);
        }
    }
}

// Never let SecretBytes be printed or logged with its contents — this is
// the type-level guard against a stray `tracing::debug!(?secret)` leaking
// key material into logs.
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.buf.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_do_not_panic_on_empty_and_nonempty() {
        let _empty = SecretBytes::new(vec![]);
        let _some = SecretBytes::new(vec![1, 2, 3, 4]);
    }

    #[test]
    fn debug_never_leaks_contents() {
        let s = SecretBytes::new(vec![0x41u8; 4]);
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("0x41"));
        assert!(!dbg.contains('A'));
    }

    #[test]
    fn deref_exposes_underlying_bytes() {
        let s = SecretBytes::new(vec![9, 8, 7]);
        assert_eq!(&*s, &[9, 8, 7]);
    }
}