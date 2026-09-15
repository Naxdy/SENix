//! A read-only pass-through filesystem over an existing directory.
//!
//! [`MetaFs`] exposes an existing filesystem tree (the *source*) through FUSE
//! while strictly forbidding any write to it or its contents:
//!
//! * every mutation operation — `create`, `write`, `rename`, `setattr`, … —
//!   is answered with `EROFS`, so nothing can ever pollute the source;
//! * every read operation is passed through to the source and its exact
//!   result forwarded back;
//! * extended attributes are stored in an in-memory map keyed by inode number
//!   ([`XattrStore`]), so a process such as `SELinux` can label files without
//!   ever writing to the underlying filesystem.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use nix::sys::statvfs;
use std::time::UNIX_EPOCH;

use crate::xattrs::{SetError, XattrStore};

/// How long the kernel may cache lookups and attributes.
const TTL: Duration = Duration::from_secs(1);

/// A single entry of a cached directory listing.
struct ListingEntry {
    name: std::ffi::OsString,
    ino: u64,
    kind: FileType,
    attr: FileAttr,
}

/// Bookkeeping for one inode known to the kernel.
struct Node {
    /// Path of the same object on the underlying filesystem.
    path: PathBuf,
    /// Overlay inode number of the parent directory.
    parent: u64,
}

/// The metacopy-style pass-through filesystem.
///
/// All fields are interior-mutable and the type is `Send + Sync`, so one
/// instance is shared by every request-handling thread.
pub struct MetaFs {
    /// File descriptor for the backing root directory, opened *before* the
    /// overlay is mounted. Every backing access is addressed through it, so
    /// the overlay can even be stacked directly on top of its own source
    /// (source == mountpoint) without re-entering this FUSE mount.
    source_fd: File,
    /// `/proc/self/fd/<fd>` prefix that resolves to the real backing directory
    /// regardless of what is mounted at the source path.
    backing_root: PathBuf,
    /// Overlay inode number -> underlying path / parent overlay inode.
    ///
    /// The reserved root inode (`INodeNo::ROOT`, i.e. 1) is never stored here;
    /// it is resolved to [`Self::backing_root`] directly.
    inodes: DashMap<u64, Node>,
    /// Open file handle -> underlying file object.
    open_files: DashMap<u64, File>,
    /// Cached, name-sorted directory listings. The source is immutable, so a
    /// listing never goes stale.
    listings: DashMap<u64, Arc<Vec<ListingEntry>>>,
    /// The only mutable state: in-memory extended attributes.
    xattrs: XattrStore,
    /// Monotonically increasing source for file handle values.
    next_fh: AtomicU64,
}

impl MetaFs {
    /// Create a filesystem backed by `source`.
    ///
    /// `source` must exist and be a directory and may be the same path as the
    /// mountpoint: all backing accesses are resolved through a descriptor
    /// opened here, before any overlay mount shadows the path.
    ///
    /// # Errors
    ///
    /// Returns an error if `source` cannot be opened or is not a directory.
    pub fn new(source: &Path) -> io::Result<Self> {
        let source_fd = File::open(source)?;
        if !source_fd.metadata()?.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("source is not a directory: {}", source.display()),
            ));
        }
        let backing_root = PathBuf::from(format!("/proc/self/fd/{}", source_fd.as_raw_fd()));
        Ok(Self {
            source_fd,
            backing_root,
            inodes: DashMap::new(),
            open_files: DashMap::new(),
            listings: DashMap::new(),
            xattrs: XattrStore::new(),
            next_fh: AtomicU64::new(1),
        })
    }

    /// Resolve an overlay inode number to an addressable path on the backing
    /// filesystem. The path always goes through the pre-opened directory
    /// descriptor, so it reaches the real filesystem even when the overlay is
    /// mounted on top of the source path itself.
    fn underlying_path(&self, ino: INodeNo) -> Option<PathBuf> {
        if ino == INodeNo::ROOT {
            Some(self.backing_root.clone())
        } else {
            self.inodes.get(&ino.0).map(|node| node.path.clone())
        }
    }

    /// Register the inode -> path mapping after a stat, unless it collides with
    /// the reserved root inode (which never happens in practice on Linux
    /// filesystems, where inode 1 is not assigned to user-visible files).
    fn remember(&self, ino: INodeNo, path: PathBuf, parent: INodeNo) {
        if ino != INodeNo::ROOT {
            self.inodes.entry(ino.0).or_insert(Node {
                path,
                parent: parent.0,
            });
        }
    }

    /// Build the `FileAttr` equivalent of `lstat(2)` on `path`.
    fn build_attr(path: &Path) -> io::Result<FileAttr> {
        Self::file_attr_from_md(&fs::symlink_metadata(path)?)
    }

    /// Build the `FileAttr` for an overlay inode.
    ///
    /// The root is read through the pre-opened backing descriptor (fstat), so
    /// this yields the real directory attributes even when the overlay is
    /// stacked directly on top of its own source.
    fn build_attr_for(&self, ino: INodeNo) -> io::Result<FileAttr> {
        if ino == INodeNo::ROOT {
            return Self::file_attr_from_md(&self.source_fd.metadata()?);
        }
        let path = self.underlying_path(ino).ok_or_else(|| {
            io::Error::new(ErrorKind::NotFound, format!("no path for inode {ino}"))
        })?;
        Self::build_attr(&path)
    }

    /// Convert raw metadata into the `FileAttr` we report to the kernel.
    fn file_attr_from_md(md: &fs::Metadata) -> io::Result<FileAttr> {
        let kind = FileType::from_std(md.file_type()).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("unknown file type for inode {}", md.ino()),
            )
        })?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(FileAttr {
            ino: INodeNo(md.ino()),
            size: md.len(),
            blocks: md.blocks(),
            atime: md.accessed().unwrap_or(UNIX_EPOCH),
            mtime: md.modified().unwrap_or(UNIX_EPOCH),
            ctime: UNIX_EPOCH
                .checked_add(Duration::from_secs(
                    u64::try_from(md.ctime().max(0)).unwrap_or(0),
                ))
                .unwrap_or(UNIX_EPOCH),
            crtime: md.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm: (md.mode() & 0o7777) as u16,
            nlink: md.nlink() as u32,
            uid: md.uid(),
            gid: md.gid(),
            rdev: md.rdev() as u32,
            flags: 0,
            blksize: 4096,
        })
    }

    /// Return the cached, name-sorted listing for a directory inode, building
    /// and caching it on first use.
    fn dir_listing(&self, ino: INodeNo) -> io::Result<Arc<Vec<ListingEntry>>> {
        if let Some(listing) = self.listings.get(&ino.0) {
            return Ok(Arc::clone(&listing));
        }

        let dir_path = self.underlying_path(ino).ok_or_else(|| {
            io::Error::new(ErrorKind::NotFound, format!("no path for inode {ino}"))
        })?;
        let dir_attr = self.build_attr_for(ino)?;
        // The ".." entry should reference the parent directory. The root's
        // parent is itself (the mount boundary).
        let parent_ino = self.inodes.get(&ino.0).map_or(ino.0, |node| node.parent);

        let mut entries = vec![
            ListingEntry {
                name: ".".into(),
                ino: ino.0,
                kind: FileType::Directory,
                attr: dir_attr,
            },
            ListingEntry {
                name: "..".into(),
                ino: parent_ino,
                kind: FileType::Directory,
                attr: dir_attr,
            },
        ];

        for child in fs::read_dir(&dir_path)? {
            let child = child?;
            let child_path = child.path();
            let attr = Self::build_attr(&child_path)?;
            self.remember(attr.ino, child_path, ino);
            entries.push(ListingEntry {
                name: child.file_name(),
                ino: attr.ino.0,
                kind: attr.kind,
                attr,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let listing = Arc::new(entries);
        self.listings.insert(ino.0, Arc::clone(&listing));
        Ok(listing)
    }
}

/// Fill `buf` from `file` starting at `offset`, returning the number of bytes
/// actually read (less than `buf.len()` only at end of file).
fn read_full_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        let n = file.read_at(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

impl Filesystem for MetaFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Ask the kernel to use READDIRPLUS and cache directory contents; both
        // are safe because the source never changes. Ignored on kernels too old
        // to support them (the plain readdir fallback still works).
        let _ = config.add_capabilities(InitFlags::FUSE_DO_READDIRPLUS);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(name);
        match Self::build_attr(&path) {
            Ok(attr) => {
                self.remember(attr.ino, path, parent);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.build_attr_for(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e.into()),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // chmod / chown / truncate / utimes would modify the underlying file;
        // reject it instead.
        reply.error(Errno::EROFS);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs::read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_encoded_bytes()),
            Err(e) => reply.error(e.into()),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EROFS);
    }

    fn mkdir(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EROFS);
    }

    fn unlink(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EROFS);
    }

    fn rmdir(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EROFS);
    }

    fn symlink(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _link_name: &OsStr,
        _target: &Path,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EROFS);
    }

    fn rename(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EROFS);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EROFS);
    }

    #[cfg(target_os = "macos")]
    fn exchange(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _options: u64,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EROFS);
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match File::open(&path) {
            Ok(file) => {
                let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
                self.open_files.insert(fh, file);
                // Nothing can invalidate the page cache, so keep it around.
                reply.opened(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE);
            }
            Err(e) => reply.error(e.into()),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let mut buf = vec![0u8; size as usize];
        // Prefer the open handle; fall back to opening by path for reads that
        // arrive without a prior `open` (e.g. kernel read-ahead).
        let result = if let Some(file) = self.open_files.get(&fh.0) {
            read_full_at(&file, &mut buf, offset)
        } else {
            let Some(path) = self.underlying_path(ino) else {
                reply.error(Errno::ENOENT);
                return;
            };
            File::open(&path).and_then(|file| read_full_at(&file, &mut buf, offset))
        };

        match result {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => reply.error(e.into()),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        reply.error(Errno::EROFS);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Nothing is buffered in userspace; the source is authoritative.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files.remove(&fh.0);
        reply.ok();
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(
            FileHandle(0),
            FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR,
        );
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let listing = match self.dir_listing(ino) {
            Ok(listing) => listing,
            Err(e) => {
                reply.error(e.into());
                return;
            }
        };
        for (i, entry) in listing
            .iter()
            .enumerate()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        {
            if reply.add(INodeNo(entry.ino), (i + 1) as u64, entry.kind, &entry.name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let listing = match self.dir_listing(ino) {
            Ok(listing) => listing,
            Err(e) => {
                reply.error(e.into());
                return;
            }
        };
        for (i, entry) in listing
            .iter()
            .enumerate()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        {
            if reply.add(
                INodeNo(entry.ino),
                (i + 1) as u64,
                &entry.name,
                &TTL,
                &entry.attr,
                Generation(0),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        #[allow(clippy::cast_possible_truncation)]
        match statvfs::statvfs(&path) {
            Ok(st) => reply.statfs(
                st.blocks(),
                st.blocks_free(),
                st.blocks_available(),
                st.files(),
                st.files_free(),
                st.fragment_size() as u32,
                st.name_max() as u32,
                st.fragment_size() as u32,
            ),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        match self
            .xattrs
            .set(ino.0, name.to_os_string(), value.to_vec(), flags)
        {
            Ok(()) => reply.ok(),
            Err(SetError::Exists) => reply.error(Errno::EEXIST),
            Err(SetError::NoAttribute) => reply.error(Errno::NO_XATTR),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let Some(value) = self.xattrs.get(ino.0, name) else {
            reply.error(Errno::NO_XATTR);
            return;
        };
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        if size == 0 {
            reply.size(len);
        } else if len > size {
            reply.error(Errno::ERANGE);
        } else {
            reply.data(&value);
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let names = self.xattrs.list(ino.0);
        // Each name is NUL-terminated in the wire format.
        let total = u32::try_from(names.iter().map(|n| n.len()).sum::<usize>() + names.len())
            .unwrap_or(u32::MAX);
        if size == 0 {
            reply.size(total);
        } else if total > size {
            reply.error(Errno::ERANGE);
        } else {
            let mut buf = Vec::with_capacity(total as usize);
            for name in &names {
                buf.extend_from_slice(name.as_encoded_bytes());
                buf.push(0);
            }
            reply.data(&buf);
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.xattrs.remove(ino.0, name) {
            reply.ok();
        } else {
            reply.error(Errno::NO_XATTR);
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let flags = nix::unistd::AccessFlags::from_bits_truncate(mask.bits());
        match nix::unistd::access(&path, flags) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Errno::from_i32(e as i32)),
        }
    }

    fn create(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        reply.error(Errno::EROFS);
    }

    fn fallocate(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _length: u64,
        _mode: i32,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EROFS);
    }
}
