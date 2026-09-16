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
    Generation, INodeNo, InitFlags, IoctlFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry,
    ReplyIoctl, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use log::{debug, error};
use std::time::UNIX_EPOCH;

use crate::xattrs::{SetError, XattrStore};

/// Most recently entered request handler, by index (diagnostics: reveals which
/// handler is in flight if a request is being lost / stuck).
static LAST_OP: AtomicU64 = AtomicU64::new(0);
const OP_NAMES: [&str; 16] = [
    "lookup",
    "getattr",
    "setattr",
    "readlink",
    "open",
    "read",
    "write",
    "readdir",
    "readdirplus",
    "release",
    "access",
    "statfs",
    "setxattr",
    "getxattr",
    "listxattr",
    "removexattr",
];

/// Record that a request handler has been entered.
fn mark_op(index: usize) {
    LAST_OP.store((index + 1) as u64, Ordering::Relaxed);
}

/// Name of the most recently entered handler (for the diagnostics heartbeat).
pub fn last_op() -> &'static str {
    OP_NAMES
        .get(
            usize::try_from(LAST_OP.load(Ordering::Relaxed))
                .unwrap_or(0)
                .saturating_sub(1),
        )
        .copied()
        .unwrap_or("none")
}

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
    /// overlay is mounted. The daemon's working directory is switched into it
    /// so that every backing path can be resolved *relative to the descriptor*
    /// (never through the process root). That keeps the backing reachable even
    /// after an initrd root switch detaches the old path tree — exactly like
    /// the open handle itself — and also when the overlay is stacked directly
    /// on top of its own source.
    source_fd: File,
    /// Whether the kernel negotiated `FUSE_PASSTHROUGH` at INIT time; gates the
    /// passthrough path in `open` (older kernels fall back to the proxy).
    passthrough: std::sync::atomic::AtomicBool,
    /// Count of FUSE requests served (diagnostics: reveals whether the kernel
    /// is still routing requests to us after an initrd root switch).
    requests: Arc<AtomicU64>,
    /// Overlay inode number -> underlying (working-directory-relative) path /
    /// parent overlay inode.
    ///
    /// The reserved root inode (`INodeNo::ROOT`, i.e. 1) is never stored here;
    /// it resolves to the working directory itself (`.`).
    inodes: DashMap<u64, Node>,
    /// Open file handle -> underlying file object.
    open_files: DashMap<u64, File>,
    /// Overlay inode -> the kernel passthrough backing ID, kept alive for the
    /// lifetime of the process. Only one backing ID may be handed to the
    /// kernel per inode, and it must stay alive for as long as any open
    /// handle exists, so we never drop it.
    backings: DashMap<u64, Arc<fuser::BackingId>>,
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
    /// mountpoint. The daemon's working directory is switched into the backing
    /// directory (via `fchdir` on the opened descriptor), after which all
    /// backing accesses are expressed relative to that directory.
    ///
    /// # Errors
    ///
    /// Returns an error if `source` cannot be opened, is not a directory, or
    /// if `fchdir` fails.
    pub fn new(source: &Path) -> io::Result<Self> {
        let source_fd = File::open(source)?;
        if !source_fd.metadata()?.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("source is not a directory: {}", source.display()),
            ));
        }
        // Anchor the process working directory to the backing directory so
        // that relative paths resolve directly from the descriptor's dentry,
        // independent of the process root (which may no longer resolve after
        // an initrd root switch).
        nix::unistd::fchdir(&source_fd).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        debug!(
            "metafs: backing via dirfd={}, source={}",
            source_fd.as_raw_fd(),
            source.display()
        );
        Ok(Self {
            source_fd,
            passthrough: std::sync::atomic::AtomicBool::new(false),
            requests: Arc::new(AtomicU64::new(0)),
            inodes: DashMap::new(),
            open_files: DashMap::new(),
            backings: DashMap::new(),
            listings: DashMap::new(),
            xattrs: XattrStore::new(),
            next_fh: AtomicU64::new(1),
        })
    }

    /// Resolve an overlay inode number to a working-directory-relative path on
    /// the backing filesystem. The root resolves to `.` (the directory the
    /// daemon is anchored in), every other inode to the stored relative path.
    fn underlying_path(&self, ino: INodeNo) -> Option<PathBuf> {
        if ino == INodeNo::ROOT {
            Some(PathBuf::from("."))
        } else {
            self.inodes.get(&ino.0).map(|node| node.path.clone())
        }
    }

    /// Shared count of requests served so far (for the diagnostics heartbeat).
    pub fn requests(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.requests)
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
        let md = fs::symlink_metadata(path).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                debug!("metafs: backing lstat {}: {e}", path.display());
            } else {
                error!("metafs: backing lstat {} failed: {e}", path.display());
            }
            e
        })?;
        let attr = Self::file_attr_from_md(&md)?;
        if attr.kind == FileType::RegularFile && attr.perm & 0o111 == 0 {
            log::debug!(
                "metafs: non-exec regular {} perm={:#06o} size={}",
                path.display(),
                attr.perm,
                attr.size
            );
        }
        Ok(attr)
    }

    /// Build the `FileAttr` for an overlay inode.
    ///
    /// The root is read through the pre-opened backing descriptor (fstat), so
    /// this yields the real directory attributes even when the overlay is
    /// stacked directly on top of its own source.
    fn build_attr_for(&self, ino: INodeNo) -> io::Result<FileAttr> {
        if ino == INodeNo::ROOT {
            return match self.source_fd.metadata() {
                Ok(md) => Self::file_attr_from_md(&md),
                Err(e) => {
                    error!(
                        "metafs: fstat of backing fd {} failed: {e}",
                        self.source_fd.as_raw_fd()
                    );
                    Err(e)
                }
            };
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

        match fs::read_dir(&dir_path) {
            Ok(reader) => {
                for child in reader {
                    match child {
                        Ok(child) => {
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
                        Err(e) => {
                            error!("metafs: read_dir {} entry failed: {e}", dir_path.display());
                            return Err(e);
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    "metafs: read_dir {} for ino {ino} failed: {e}",
                    dir_path.display()
                );
                return Err(e);
            }
        }

        debug!(
            "metafs: listing {ino} via {}: {} real entries",
            dir_path.display(),
            entries.len().saturating_sub(2)
        );
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
        // Ask the kernel to use READDIRPLUS / directory caching and, most
        // importantly, FUSE passthrough (kernel >= 6.9). With passthrough the
        // kernel forwards reads straight to the backing fd registered in
        // `open`, so the data plane is handled entirely by the kernel.
        let _ = config.add_capabilities(InitFlags::FUSE_DO_READDIRPLUS);
        self.passthrough.store(
            config.add_capabilities(InitFlags::FUSE_PASSTHROUGH).is_ok(),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        mark_op(0);
        self.requests.fetch_add(1, Ordering::Relaxed);
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
        mark_op(1);
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
        mark_op(2); // chmod / chown / truncate / utimes would modify the underlying file;
        // reject it instead.
        reply.error(Errno::EROFS);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        mark_op(3);
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
        mark_op(4);
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("metafs: open {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);

        // Keep a private copy so the fallback `read` path still works on
        // kernels without passthrough support; the kernel itself registers
        // the (duplicated) backing fd through the `open_backing` ioctl.
        if let Ok(copy) = file.try_clone() {
            self.open_files.insert(fh, copy);
        }

        // Register the backing file for kernel passthrough and reuse a single
        // BackingId per inode, as the kernel requires. If unavailable, fall
        // back to the classic proxied open (our read handler takes over).
        if !self.passthrough.load(Ordering::Relaxed) {
            reply.opened(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE);
            return;
        }
        match reply.open_backing(&file) {
            Ok(backing) => {
                let entry = self
                    .backings
                    .entry(ino.0)
                    .or_insert_with(|| Arc::new(backing));
                reply.opened_passthrough(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE, &entry);
            }
            Err(e) => {
                debug!(
                    "metafs: passthrough unavailable for {}: {e}",
                    path.display()
                );
                reply.opened(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE);
            }
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
        mark_op(5);
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
        mark_op(6);
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
        mark_op(9);
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
        mark_op(7);
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
        mark_op(8);
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        mark_op(11);
        #[allow(clippy::cast_possible_truncation)]
        match nix::sys::statvfs::fstatvfs(&self.source_fd) {
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
        mark_op(12);
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
        mark_op(13);
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
        mark_op(14);
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
        mark_op(15);
        if self.xattrs.remove(ino.0, name) {
            reply.ok();
        } else {
            reply.error(Errno::NO_XATTR);
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        mark_op(10);
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let flags = nix::unistd::AccessFlags::from_bits_truncate(mask.bits());
        if let Err(e) = nix::unistd::access(&path, flags) {
            match &e {
                nix::errno::Errno::ENOENT => debug!("metafs: access {}: {e}", path.display()),
                _ => error!(
                    "metafs: access {} mask={} failed: {e}",
                    path.display(),
                    mask
                ),
            }
            reply.error(Errno::from_i32(e as i32));
        } else {
            reply.ok();
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

    fn ioctl(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: IoctlFlags,
        _cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        if in_data.is_empty() && out_size == 0 {
            // Nothing to shuttle; ack the probe without attempting to fill
            // caller-provided buffers (fuser would reject those later).
            reply.ioctl(0, &[]);
        } else {
            // Unsupported ioctls on regular files. Quietly report ENOSYS so
            // callers fall back to generic handling (this also avoids fuser's
            // per-request "not implemented" warning flooding the console).
            reply.error(Errno::ENOSYS);
        }
    }
}
