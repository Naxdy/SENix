//! A read-only pass-through filesystem over an existing directory.
//!
//! [`MetaFs`] exposes an existing filesystem tree (the *source*) through FUSE as
//! a faithful read-write pass-through overlay:
//!
//! * every operation — reads, writes, and structural mutations such as
//!   `create`, `mkdir`, `unlink`, `rename`, `setattr` — is passed through to
//!   the source exactly like the kernel would use it directly;
//! * read and write *content* I/O is handed to the kernel as FUSE passthrough,
//!   which uses an open descriptor of the backing file directly and never
//!   round-trips through this process;
//! * extended attributes are stored in an in-memory map keyed by inode number
//!   ([`XattrStore`]), so a process such as `SELinux` can label files without
//!   ever writing to the underlying filesystem.
//!
//! Making the filesystem read-only for the outside world is deliberately left
//! to the mount table (`MS_RDONLY`): nothing in this crate forces it, so the
//! Nix daemon can simply remount the store read-write inside its own private
//! mount namespace while every other process still sees a read-only overlay.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, IoctlFlags, KernelConfig, LockOwner, OpenAccMode, OpenFlags,
    RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty,
    ReplyEntry, ReplyIoctl, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    WriteFlags,
};
use log::{debug, error};
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

/// A faithful pass-through filesystem with in-memory extended attributes.
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
    /// Count of FUSE requests served (diagnostics: reveals whether the kernel
    /// is still routing requests to us after an initrd root switch).
    requests: Arc<AtomicU64>,
    /// Overlay inode number -> underlying (working-directory-relative) path /
    /// parent overlay inode.
    ///
    /// The reserved root inode (`INodeNo::ROOT`, i.e. 1) is never stored here;
    /// it resolves to the working directory itself (`.`).
    inodes: DashMap<u64, Node>,
    /// Overlay inode -> the kernel passthrough backing ID, kept alive for the
    /// lifetime of the process. Only one backing ID may be handed to the
    /// kernel per inode, and it must stay alive for as long as any open
    /// handle exists, so we never drop it.
    backings: DashMap<u64, Arc<fuser::BackingId>>,
    /// Cached, name-sorted directory listings. The cache is invalidated by
    /// every structural mutation (create, unlink, rename, ...), since the
    /// source is now writable.
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
            requests: Arc::new(AtomicU64::new(0)),
            inodes: DashMap::new(),
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

    /// Convert a nix errno into an `io::Error` for reply propagation.
    fn errno(e: nix::errno::Errno) -> io::Error {
        io::Error::from_raw_os_error(e as i32)
    }

    /// Apply `atime`/`mtime` to the backing file behind `path`.
    ///
    /// `TimeOrNow::Now` is expressed as `UTIME_NOW` so the kernel can stamp the
    /// current time itself.
    fn set_times(path: &Path, atime: TimeOrNow, mtime: TimeOrNow) -> io::Result<()> {
        use std::ffi::CString;
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())?;
        let mut times = [libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }; 2];
        for (slot, time) in times.iter_mut().zip([atime, mtime]) {
            match time {
                TimeOrNow::SpecificTime(t) => {
                    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                    slot.tv_sec = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                    slot.tv_nsec = i64::from(d.subsec_nanos());
                }
                TimeOrNow::Now => slot.tv_nsec = libc::UTIME_NOW,
            }
        }
        // SAFETY: `c_path` is NUL-terminated and remains valid for the call;
        // `times` points to a 2-element array the kernel validates.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Self::errno(nix::errno::Errno::last()))
        }
    }

    /// Common tail for operations that materialize a new directory entry
    /// (`mkdir`, `symlink`, `link`, `mknod`): drop the parent's cached listing
    /// (it is now stale), register the new inode, and return its attributes.
    ///
    /// Callers must ensure the entry already exists on the backing filesystem.
    fn attr_after_create(&self, path: PathBuf, parent: INodeNo) -> io::Result<FileAttr> {
        let attr = Self::build_attr(&path)?;
        self.remember(attr.ino, path, parent);
        self.listings.remove(&parent.0);
        Ok(attr)
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

impl Filesystem for MetaFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Ask the kernel to use READDIRPLUS / directory caching and, most
        // importantly, FUSE passthrough (assumed available). Passthrough does
        // not become active until the connection's `max_stack_depth` is > 0
        // (the kernel refuses the backing-open ioctl with EPERM otherwise);
        // 2 also permits backing files on a stacked filesystem (e.g. the
        // NixOS store overlay). No userspace read proxy is involved.
        let _ = config.add_capabilities(InitFlags::FUSE_DO_READDIRPLUS);
        let _ = config.add_capabilities(InitFlags::FUSE_PASSTHROUGH);
        let _ = config.set_max_stack_depth(2);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
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
        match self.build_attr_for(ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e.into()),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Apply attribute changes to the backing file; this is a genuine
        // read-write pass-through.
        if let Some(mode) = mode {
            let perms = fs::Permissions::from_mode(mode & 0o7777);
            if let Err(e) = fs::set_permissions(&path, perms) {
                error!("metafs: chmod {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        }
        if uid.is_some() || gid.is_some() {
            let u = uid.map(nix::unistd::Uid::from_raw);
            let g = gid.map(nix::unistd::Gid::from_raw);
            if let Err(e) = nix::unistd::chown(&path, u, g) {
                error!("metafs: chown {} failed: {e}", path.display());
                reply.error(Errno::from_i32(e as i32));
                return;
            }
        }
        if let Some(size) = size {
            match File::options().write(true).open(&path) {
                Ok(f) => {
                    if let Err(e) = f.set_len(size) {
                        error!("metafs: truncate {} failed: {e}", path.display());
                        reply.error(e.into());
                        return;
                    }
                }
                Err(e) => {
                    error!("metafs: truncate open {} failed: {e}", path.display());
                    reply.error(e.into());
                    return;
                }
            }
        }
        if (atime.is_some() || mtime.is_some())
            && let Err(e) = Self::set_times(
                &path,
                atime.unwrap_or(TimeOrNow::Now),
                mtime.unwrap_or(TimeOrNow::Now),
            )
        {
            error!("metafs: utimens {} failed: {e}", path.display());
            reply.error(e.into());
            return;
        }
        match Self::build_attr(&path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e.into()),
        }
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
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(name);
        let mode = mode & 0o7777 & !umask;
        let kind = mode & libc::S_IFMT;
        let result: io::Result<()> = match kind {
            libc::S_IFREG => File::options()
                .create_new(true)
                .write(true)
                .open(&path)
                .map(|_| ()),
            libc::S_IFIFO => std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_or_else(
                    |_| Err(ErrorKind::InvalidData.into()),
                    |c_path| {
                        // SAFETY: `c_path` is NUL-terminated; mode is a valid file type.
                        let rc = unsafe {
                            libc::mkfifo(c_path.as_ptr(), (mode | libc::S_IFIFO) as libc::mode_t)
                        };
                        if rc == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::from_raw_os_error(nix::errno::Errno::last_raw()))
                        }
                    },
                ),
            libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK => {
                let flag = match kind {
                    libc::S_IFCHR => nix::sys::stat::SFlag::S_IFCHR,
                    libc::S_IFBLK => nix::sys::stat::SFlag::S_IFBLK,
                    _ => nix::sys::stat::SFlag::S_IFSOCK,
                };
                // FUSE encodes device numbers with the legacy scheme; decode
                // before handing them to mknod.
                let major = ((rdev >> 8) & 0xfff) as libc::c_uint;
                let minor = ((rdev & 0xff) | ((rdev >> 12) & 0xfff00)) as libc::c_uint;
                nix::sys::stat::mknod(
                    &path,
                    flag,
                    nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t),
                    libc::makedev(major, minor),
                )
                .map_err(Self::errno)
            }
            _ => Err(ErrorKind::Unsupported.into()),
        };
        match result.and_then(|()| self.attr_after_create(path, parent)) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => {
                if kind == libc::S_IFREG {
                    log::debug!("metafs: mknod {}: {e}", parent_path.join(name).display());
                }
                reply.error(e.into());
            }
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(name);
        let result = nix::unistd::mkdir(
            &path,
            nix::sys::stat::Mode::from_bits_truncate(mode & !umask),
        )
        .map_err(Self::errno)
        .and_then(|()| self.attr_after_create(path, parent));
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e.into()),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs::remove_file(parent_path.join(name)) {
            Ok(()) => {
                self.listings.remove(&parent.0);
                reply.ok();
            }
            Err(e) => {
                debug!(
                    "metafs: unlink {}/{}: {e}",
                    parent_path.display(),
                    name.to_string_lossy()
                );
                reply.error(e.into());
            }
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs::remove_dir(parent_path.join(name)) {
            Ok(()) => {
                self.listings.remove(&parent.0);
                reply.ok();
            }
            Err(e) => {
                debug!(
                    "metafs: rmdir {}/{}: {e}",
                    parent_path.display(),
                    name.to_string_lossy()
                );
                reply.error(e.into());
            }
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(link_name);
        let result = symlink(target, &path).and_then(|()| self.attr_after_create(path, parent));
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e.into()),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (Some(parent_path), Some(new_parent_path)) = (
            self.underlying_path(parent),
            self.underlying_path(newparent),
        ) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let from = parent_path.join(name);
        let to = new_parent_path.join(newname);
        // Capture the moved inode so its path mapping can follow it.
        let moved_ino = Self::build_attr(&from).ok().map(|a| a.ino.0);
        match fs::rename(&from, &to) {
            Ok(()) => {
                if let Some(ino) = moved_ino
                    && let Some(mut node) = self.inodes.get_mut(&ino)
                {
                    node.path = to;
                    node.parent = newparent.0;
                }
                self.listings.remove(&parent.0);
                self.listings.remove(&newparent.0);
                reply.ok();
            }
            Err(e) => {
                error!(
                    "metafs: rename {} -> {} failed: {e}",
                    from.display(),
                    to.display()
                );
                reply.error(e.into());
            }
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let (Some(old_path), Some(new_parent_path)) =
            (self.underlying_path(ino), self.underlying_path(newparent))
        else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = new_parent_path.join(newname);
        // A hard link shares the *same* inode, so `remember` keeps the existing
        // path mapping (identical content either way).
        let result =
            fs::hard_link(&old_path, &path).and_then(|()| self.attr_after_create(path, newparent));
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e.into()),
        }
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

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Open the backing with the requested access mode so the kernel can
        // forward both reads and writes straight through: passthrough I/O uses
        // this exact descriptor, and a read-only fd cannot serve forwarded
        // writes.
        let write = flags.acc_mode() != OpenAccMode::O_RDONLY;
        let mut options = File::options();
        options.read(true);
        if write {
            options.write(true);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("metafs: open {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);

        // FUSE passthrough: register the backing file with the kernel so
        // reads are served straight from this fd. The kernel refuses a
        // different backing ID for an inode that already has one, so reuse a
        // single BackingId per inode (kept alive for the process lifetime).
        match reply.open_backing(&file) {
            Ok(backing) => {
                let entry = self
                    .backings
                    .entry(ino.0)
                    .or_insert_with(|| Arc::new(backing));
                reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &entry);
            }
            Err(e) => {
                log::warn!(
                    "metafs: passthrough unavailable for {}: {e}",
                    path.display()
                );
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        // Normally the kernel forwards writes straight to the passthrough
        // backing fd and this handler is never entered. If one does arrive
        // (e.g. an open whose passthrough registration failed), write through
        // to the backing filesystem exactly as the kernel would.
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let file = match File::options().write(true).open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("metafs: write open {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        match file.write_all_at(data, offset) {
            Ok(()) => {
                let written = u32::try_from(data.len()).unwrap_or(u32::MAX);
                reply.written(written);
            }
            Err(e) => reply.error(e.into()),
        }
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
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // The backing BackingId is intentionally kept alive for the process
        // lifetime; nothing to release in userspace.
        reply.ok();
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        // Keep the page-cache flag for file content but not the directory-
        // entry cache: this filesystem is mutable, and `self.listings` (which
        // we invalidate on every structural change) is the only authoritative
        // readdir source.
        reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE);
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

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
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
        let path = self
            .underlying_path(ino)
            .map_or_else(|| "?".into(), |p| p.display().to_string());
        let value_dbg = if name == OsStr::new("security.selinux") {
            format!("{value:?}")
        } else {
            format!("<{} bytes>", value.len())
        };
        log::debug!(
            "metafs: SETXATTR ino={} {} flags={flags} path={} value={value_dbg}",
            ino.0,
            name.to_string_lossy(),
            path
        );
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
            log::debug!(
                "metafs: GETXATTR ino={} {} size={size} -> ENODATA",
                ino.0,
                name.to_string_lossy()
            );
            reply.error(Errno::NO_XATTR);
            return;
        };
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        log::debug!(
            "metafs: GETXATTR ino={} {} size={size} len={len}",
            ino.0,
            name.to_string_lossy()
        );
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
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.underlying_path(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(name);
        let write = (flags & libc::O_ACCMODE) != libc::O_RDONLY;
        let mut options = File::options();
        options.read(true);
        if write {
            options.write(true);
        }
        let file = match options.create(true).open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("metafs: create {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        // Honour the requested mode (FUSE passes the caller's umask).
        let perms = fs::Permissions::from_mode(mode & 0o7777 & !umask);
        if let Err(e) = fs::set_permissions(&path, perms) {
            debug!("metafs: create chmod {}: {e}", path.display());
        }
        let md = match file.metadata() {
            Ok(md) => md,
            Err(e) => {
                error!("metafs: create stat {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        let attr = match Self::file_attr_from_md(&md) {
            Ok(attr) => attr,
            Err(e) => {
                error!("metafs: create stat {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        self.remember(attr.ino, path.clone(), parent);
        self.listings.remove(&parent.0);
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        match reply.open_backing(&file) {
            Ok(backing) => {
                let entry = self
                    .backings
                    .entry(attr.ino.0)
                    .or_insert_with(|| Arc::new(backing));
                reply.created_passthrough(
                    &TTL,
                    &attr,
                    Generation(0),
                    FileHandle(fh),
                    FopenFlags::empty(),
                    &entry,
                );
            }
            Err(e) => {
                log::warn!(
                    "metafs: passthrough unavailable for {}: {e}",
                    path.display()
                );
                reply.created(
                    &TTL,
                    &attr,
                    Generation(0),
                    FileHandle(fh),
                    FopenFlags::empty(),
                );
            }
        }
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let Some(path) = self.underlying_path(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let file = match File::options().write(true).open(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("metafs: fallocate open {} failed: {e}", path.display());
                reply.error(e.into());
                return;
            }
        };
        // SAFETY: `file` is a valid writable fd; the offset/length/mode are
        // directly forwarded from the caller.
        let rc = unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                mode,
                i64::try_from(offset).unwrap_or(i64::MAX),
                i64::try_from(length).unwrap_or(i64::MAX),
            )
        };
        if rc == 0 {
            reply.ok();
        } else {
            reply.error(Errno::from_i32(nix::errno::Errno::last_raw()));
        }
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
