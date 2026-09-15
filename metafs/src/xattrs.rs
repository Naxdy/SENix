//! In-memory extended-attribute store.
//!
//! The filesystem itself is strictly read-only: every operation that would
//! mutate the underlying filesystem is answered with `EROFS`. Extended
//! attributes are the one exception — they are stored entirely in memory,
//! keyed by inode number, so that consumers such as `SELinux` can attach
//! labels to files without ever writing to the underlying (immutable)
//! filesystem.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use dashmap::DashMap;

/// Requested creation of a new attribute (`setxattr(2)` without `XATTR_REPLACE`).
pub const SETXATTR_CREATE: i32 = libc::XATTR_CREATE;
/// Requested replacement of an existing attribute (`setxattr(2)` without `XATTR_CREATE`).
pub const SETXATTR_REPLACE: i32 = libc::XATTR_REPLACE;

/// Why a [`set`] could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetError {
    /// [`SETXATTR_CREATE`] was requested but the attribute already exists.
    Exists,
    /// [`SETXATTR_REPLACE`] was requested but the attribute does not exist.
    NoAttribute,
}

/// Concurrent, in-memory mapping of inode numbers to their extended attributes.
///
/// Values are stored as raw bytes, exactly as handed in by the kernel. Names
/// are kept as `OsString`s so that non-UTF-8 names are preserved. Lookups and
/// mutations are synchronized by [`DashMap`], and each inode's attribute set
/// is an order-preserving [`BTreeMap`] so that listing yields a stable, sorted
/// order.
#[derive(Default)]
pub struct XattrStore {
    by_inode: DashMap<u64, BTreeMap<OsString, Vec<u8>>>,
}

impl XattrStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store the attribute `name -> value` for `ino`.
    ///
    /// `flags` accepts `0`, [`SETXATTR_CREATE`] or [`SETXATTR_REPLACE`]. The
    /// caller maps [`SetError`] onto the corresponding `errno`.
    ///
    /// # Errors
    ///
    /// Returns [`SetError::Exists`] if `SETXATTR_CREATE` was requested and the
    /// attribute exists, or [`SetError::NoAttribute`] if `SETXATTR_REPLACE` was
    /// requested and the attribute is absent.
    pub fn set(
        &self,
        ino: u64,
        name: OsString,
        value: Vec<u8>,
        flags: i32,
    ) -> Result<(), SetError> {
        let mut attrs = self.by_inode.entry(ino).or_default();

        let create = flags & SETXATTR_CREATE != 0;
        let replace = flags & SETXATTR_REPLACE != 0;

        if create && attrs.contains_key(&name) {
            return Err(SetError::Exists);
        }
        if replace && !attrs.contains_key(&name) {
            return Err(SetError::NoAttribute);
        }

        attrs.insert(name, value);
        // Release the shard lock as soon as the mutation is done.
        drop(attrs);
        Ok(())
    }

    /// Return a copy of the value stored for `name` on `ino`, if any.
    #[must_use]
    pub fn get(&self, ino: u64, name: &OsStr) -> Option<Vec<u8>> {
        self.by_inode
            .get(&ino)
            .and_then(|attrs| attrs.get(name).cloned())
    }

    /// Return the names of all attributes stored for `ino`, sorted by name.
    #[must_use]
    pub fn list(&self, ino: u64) -> Vec<OsString> {
        self.by_inode
            .get(&ino)
            .map_or_else(Vec::new, |attrs| attrs.keys().cloned().collect())
    }

    /// Remove the attribute `name` from `ino`.
    ///
    /// Returns `true` if the attribute was present and has been removed.
    #[must_use]
    pub fn remove(&self, ino: u64, name: &OsStr) -> bool {
        self.by_inode
            .get_mut(&ino)
            .is_some_and(|mut attrs| attrs.remove(name).is_some())
    }

    /// Drop every attribute stored for `ino`.
    ///
    /// Used on `forget` so a long-lived mount does not accumulate entries for
    /// inodes the kernel has released.
    pub fn forget(&self, ino: u64) {
        self.by_inode.remove(&ino);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use super::{SETXATTR_CREATE, SETXATTR_REPLACE, XattrStore};

    fn name(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn set_and_get_roundtrip() {
        let store = XattrStore::new();
        store
            .set(7, name("user.color"), b"red".to_vec(), 0)
            .unwrap();
        assert_eq!(
            store.get(7, name("user.color").as_os_str()),
            Some(b"red".to_vec())
        );
        assert_eq!(store.get(8, name("user.color").as_os_str()), None);
    }

    #[test]
    fn set_overwrites_by_default() {
        let store = XattrStore::new();
        store
            .set(7, name("user.color"), b"red".to_vec(), 0)
            .unwrap();
        store
            .set(7, name("user.color"), b"blue".to_vec(), 0)
            .unwrap();
        assert_eq!(
            store.get(7, name("user.color").as_os_str()),
            Some(b"blue".to_vec())
        );
    }

    #[test]
    fn set_create_honoured() {
        let store = XattrStore::new();
        store
            .set(7, name("user.color"), b"red".to_vec(), SETXATTR_CREATE)
            .unwrap();
        let second = store.set(7, name("user.color"), b"blue".to_vec(), SETXATTR_CREATE);
        assert_eq!(second, Err(super::SetError::Exists));
    }

    #[test]
    fn set_replace_honoured() {
        let store = XattrStore::new();
        let before = store.set(7, name("user.color"), b"red".to_vec(), SETXATTR_REPLACE);
        assert_eq!(before, Err(super::SetError::NoAttribute));
        store
            .set(7, name("user.color"), b"red".to_vec(), 0)
            .unwrap();
        store
            .set(7, name("user.color"), b"blue".to_vec(), SETXATTR_REPLACE)
            .unwrap();
        assert_eq!(
            store.get(7, name("user.color").as_os_str()),
            Some(b"blue".to_vec())
        );
    }

    #[test]
    fn remove_returns_whether_present() {
        let store = XattrStore::new();
        assert!(!store.remove(7, name("user.color").as_os_str()));
        store
            .set(7, name("user.color"), b"red".to_vec(), 0)
            .unwrap();
        assert!(store.remove(7, name("user.color").as_os_str()));
        assert!(!store.remove(7, name("user.color").as_os_str()));
        assert_eq!(store.get(7, name("user.color").as_os_str()), None);
    }

    #[test]
    fn list_is_sorted_and_inode_local() {
        let store = XattrStore::new();
        store.set(7, name("user.zebra"), b"1".to_vec(), 0).unwrap();
        store.set(7, name("user.apple"), b"2".to_vec(), 0).unwrap();
        store.set(7, name("user.mango"), b"3".to_vec(), 0).unwrap();
        store
            .set(8, name("user.apple"), b"other".to_vec(), 0)
            .unwrap();
        assert_eq!(
            store.list(7),
            vec![name("user.apple"), name("user.mango"), name("user.zebra")]
        );
        assert_eq!(store.list(8), vec![name("user.apple")]);
        assert_eq!(store.list(9), Vec::<OsString>::new());
    }

    #[test]
    fn forget_drops_all_attributes_for_inode() {
        let store = XattrStore::new();
        store.set(7, name("user.a"), b"1".to_vec(), 0).unwrap();
        store.set(7, name("user.b"), b"2".to_vec(), 0).unwrap();
        store.forget(7);
        assert!(store.list(7).is_empty());
        assert_eq!(store.get(7, name("user.a").as_os_str()), None);
    }

    #[test]
    fn non_utf8_names_and_values_survive() {
        let store = XattrStore::new();
        let weird = OsString::from_vec(b"user.\xff\xfe".to_vec());
        let bytes = vec![0u8, 159, 146, 150, 0xff];
        store.set(7, weird.clone(), bytes.clone(), 0).unwrap();
        assert_eq!(store.get(7, weird.as_os_str()), Some(bytes));
        assert_eq!(store.list(7), vec![weird]);
    }

    #[test]
    fn concurrent_mutations_are_consistent() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(XattrStore::new());

        // Each thread mutates its own attribute on a shared inode; the map must
        // never tear, and every attribute must be present afterwards.
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let key = name(&format!("user.attr{t}"));
                    for i in 0..500 {
                        store
                            .set(42, key.clone(), format!("{i}").into_bytes(), 0)
                            .unwrap();
                        assert!(store.get(42, key.as_os_str()).is_some());
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        // All threads contend on one shared attribute; no matter who wins, the
        // map must stay consistent and never report corruption.
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let key = name("user.shared");
                    for i in 0..500 {
                        let value = format!("{t}-{i}");
                        store.set(43, key.clone(), value.into_bytes(), 0).unwrap();
                        assert!(store.get(43, key.as_os_str()).is_some());
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let names = store.list(42);
        assert_eq!(names.len(), 8);
        for t in 0..8 {
            let key = name(&format!("user.attr{t}"));
            assert!(store.get(42, key.as_os_str()).is_some());
        }
        assert_eq!(store.list(43), vec![name("user.shared")]);
    }
}
