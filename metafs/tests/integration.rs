//! End-to-end tests against a real FUSE mount.
//!
//! These require a kernel-provided `/dev/fuse` and are skipped silently when it
//! is unavailable (e.g. inside a Nix build sandbox). On a machine with FUSE
//! they mount `MetaFs` over a temporary directory and drive it through real
//! system calls.

#![allow(
    clippy::unwrap_used,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

use std::ffi::{CString, c_void};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fuser::{Config, MountOption};
use metafs::fs::MetaFs;
use tempfile::TempDir;

// EROFS errno value on Linux.
const EROFS: i32 = 30;

/// True when a FUSE mount can actually be established in this environment.
///
/// Merely having `/dev/fuse` is not enough: unprivileged processes still need
/// `CAP_SYS_ADMIN` or a setuid `fusermount`. Probe with a real (tiny) mount and
/// skip the test when the kernel refuses it (e.g. inside a locked-down build
/// sandbox).
fn fuse_available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse unavailable");
        return false;
    }
    let source = TempDir::new().unwrap();
    fs::write(source.path().join("probe"), b"x").unwrap();
    let mountpoint = TempDir::new().unwrap();
    match mount(source.path(), mountpoint.path()) {
        Ok(_session) => true,
        Err(e) => {
            eprintln!("skipping: cannot mount FUSE here ({e})");
            false
        }
    }
}

/// Mount `source` at `mountpoint`, returning a handle that unmounts on drop.
fn mount(source: &Path, mountpoint: &Path) -> io::Result<fuser::BackgroundSession> {
    let mut config = Config::default();
    config
        .mount_options
        .push(MountOption::FSName("metafs-test".to_string()));
    config.n_threads = Some(4);
    let fs = MetaFs::new(source)?;
    fuser::spawn_mount(fs, mountpoint, &config)
}

/// Create a small source tree for pass-through testing.
fn setup_source() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello world\n").unwrap();
    fs::write(dir.path().join("empty"), b"").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/nested.txt"), b"nested-content").unwrap();
    std::os::unix::fs::symlink("hello.txt", dir.path().join("link")).unwrap();
    dir
}

fn cpath(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn cname(name: &str) -> CString {
    CString::new(name).unwrap()
}

fn sys_setxattr(path: &Path, name: &str, value: &[u8], flags: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::setxattr(
            cpath(path).as_ptr(),
            cname(name).as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn sys_getxattr(path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let size = unsafe {
        libc::getxattr(
            cpath(path).as_ptr(),
            cname(name).as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; size as usize];
    let n = unsafe {
        libc::getxattr(
            cpath(path).as_ptr(),
            cname(name).as_ptr(),
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn sys_listxattr(path: &Path) -> io::Result<Vec<String>> {
    let size = unsafe { libc::listxattr(cpath(path).as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; size as usize];
    let n = unsafe {
        libc::listxattr(
            cpath(path).as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect())
}

fn sys_removexattr(path: &Path, name: &str) -> io::Result<()> {
    let ret = unsafe { libc::removexattr(cpath(path).as_ptr(), cname(name).as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[test]
fn read_operations_pass_through_to_underlying() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse unavailable");
        return;
    }

    let source = setup_source();
    let mountpoint = TempDir::new().unwrap();
    let _session = mount(source.path(), mountpoint.path()).unwrap();

    // Contents are forwarded exactly.
    assert_eq!(
        fs::read(mountpoint.path().join("hello.txt")).unwrap(),
        b"hello world\n"
    );
    assert_eq!(
        fs::read(mountpoint.path().join("sub/nested.txt")).unwrap(),
        b"nested-content"
    );
    assert_eq!(fs::read(mountpoint.path().join("empty")).unwrap(), b"");

    // Byte-for-byte comparison of a larger synthetic file.
    let big = vec![0xABu8; 1 << 20];
    fs::write(source.path().join("big.bin"), &big).unwrap();
    assert_eq!(fs::read(mountpoint.path().join("big.bin")).unwrap(), big);

    // Directory listing is complete, including "." and "..".
    let names: Vec<PathBuf> = fs::read_dir(mountpoint.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into())
        .collect();
    for expected in ["hello.txt", "sub", "link", "empty", "big.bin"] {
        assert!(names.iter().any(|n| n.as_os_str() == expected));
    }
    assert!(names.iter().any(|n| n.as_os_str() == "."));
    assert!(names.iter().any(|n| n.as_os_str() == ".."));

    // Stat fields (size, mode) are forwarded; the overlay inode is synthetic
    // per path, so it must be a valid nonzero id, not necessarily the backing
    // inode.
    let src_md = fs::metadata(source.path().join("hello.txt")).unwrap();
    let mnt_md = fs::metadata(mountpoint.path().join("hello.txt")).unwrap();
    assert_eq!(mnt_md.len(), src_md.len());
    assert!(mnt_md.ino() != 0);
    assert_eq!(
        mnt_md.permissions().mode() & 0o777,
        src_md.permissions().mode() & 0o777
    );

    // Symlinks are forwarded as symlinks with the same target.
    let link_meta = fs::symlink_metadata(mountpoint.path().join("link")).unwrap();
    assert!(link_meta.file_type().is_symlink());
    assert_eq!(
        fs::read_link(mountpoint.path().join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );

    // The source tree is untouched.
    assert_eq!(fs::read_dir(source.path()).unwrap().count(), 5);
    assert_eq!(fs::read_dir(source.path().join("sub")).unwrap().count(), 1);
}

#[test]
fn write_operations_return_erofs() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse unavailable");
        return;
    }

    let source = setup_source();
    let mountpoint = TempDir::new().unwrap();
    let _session = mount(source.path(), mountpoint.path()).unwrap();

    // Creating a new file is refused.
    let err = fs::File::create(mountpoint.path().join("new.txt")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(EROFS));

    // Truncating an existing file (touch on existing / O_TRUNC) is refused.
    let err = File::options()
        .write(true)
        .truncate(true)
        .open(mountpoint.path().join("hello.txt"))
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(EROFS));

    // Writing to an already-open file is refused.
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(mountpoint.path().join("hello.txt"))
        .unwrap();
    let n = file.write(b"data").unwrap_err();
    assert_eq!(n.raw_os_error(), Some(EROFS));

    // mkdir / rmdir / unlink / rename are refused.
    assert_eq!(
        fs::create_dir(mountpoint.path().join("dir"))
            .unwrap_err()
            .raw_os_error(),
        Some(EROFS)
    );
    assert_eq!(
        fs::remove_dir(mountpoint.path().join("sub"))
            .unwrap_err()
            .raw_os_error(),
        Some(EROFS)
    );
    assert_eq!(
        fs::remove_file(mountpoint.path().join("hello.txt"))
            .unwrap_err()
            .raw_os_error(),
        Some(EROFS)
    );
    assert_eq!(
        fs::rename(
            mountpoint.path().join("hello.txt"),
            mountpoint.path().join("renamed.txt"),
        )
        .unwrap_err()
        .raw_os_error(),
        Some(EROFS)
    );
    assert_eq!(
        std::os::unix::fs::symlink("hello.txt", mountpoint.path().join("sl"))
            .unwrap_err()
            .raw_os_error(),
        Some(EROFS)
    );

    // Everything is still readable afterwards.
    assert_eq!(
        fs::read(mountpoint.path().join("hello.txt")).unwrap(),
        b"hello world\n"
    );
}

#[test]
fn xattrs_are_stored_in_memory_and_leave_underlying_untouched() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse unavailable");
        return;
    }

    let source = setup_source();
    let mountpoint = TempDir::new().unwrap();
    let _session = mount(source.path(), mountpoint.path()).unwrap();

    let mnt_file = mountpoint.path().join("hello.txt");
    let src_file = source.path().join("hello.txt");

    // Nothing pre-existing on either side.
    assert!(sys_listxattr(&mnt_file).unwrap().is_empty());

    // set/get round-trip through the mount.
    sys_setxattr(&mnt_file, "user.color", b"red", 0).unwrap();
    sys_setxattr(&mnt_file, "user.alpha", b"1", 0).unwrap();
    assert_eq!(sys_getxattr(&mnt_file, "user.color").unwrap(), b"red");
    assert_eq!(
        sys_listxattr(&mnt_file).unwrap(),
        vec!["user.alpha", "user.color"]
    );

    // The underlying file must not carry the labels.
    assert!(sys_listxattr(&src_file).unwrap().is_empty());

    // XATTR_CREATE on an existing attribute is refused, XATTR_REPLACE on a
    // missing one is refused.
    assert_eq!(
        sys_setxattr(&mnt_file, "user.color", b"x", libc::XATTR_CREATE)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
    assert_eq!(
        sys_setxattr(&mnt_file, "user.missing", b"x", libc::XATTR_REPLACE)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENODATA)
    );

    // Removal works, and reading a removed attribute reports ENODATA.
    sys_removexattr(&mnt_file, "user.alpha").unwrap();
    assert_eq!(
        sys_getxattr(&mnt_file, "user.alpha")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENODATA)
    );
    assert_eq!(sys_listxattr(&mnt_file).unwrap(), vec!["user.color"]);

    // Labels are independent per inode.
    sys_setxattr(&mnt_file, "user.color", b"red", 0).unwrap();
    let mnt_sub = mountpoint.path().join("sub/nested.txt");
    sys_setxattr(&mnt_sub, "user.color", b"blue", 0).unwrap();
    assert_eq!(sys_getxattr(&mnt_sub, "user.color").unwrap(), b"blue");
    assert_eq!(sys_getxattr(&mnt_file, "user.color").unwrap(), b"red");

    // Syscall-level xattrs never touch the underlying filesystem.
    assert!(sys_listxattr(&src_file).unwrap().is_empty());
    assert!(
        sys_listxattr(&source.path().join("sub/nested.txt"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn hardlinked_paths_get_distinct_overlay_inodes_and_labels() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse unavailable");
        return;
    }

    // Mirror the Nix store content-addressed optimizer: byte-identical files
    // become hard links to one backing inode.
    let source = TempDir::new().unwrap();
    let a_path = source.path().join("a.conf");
    let b_path = source.path().join("b.conf");
    fs::write(&a_path, b"shared-content\n").unwrap();
    fs::hard_link(&a_path, &b_path).unwrap();
    assert_eq!(
        fs::metadata(&a_path).unwrap().ino(),
        fs::metadata(&b_path).unwrap().ino()
    );

    let mountpoint = TempDir::new().unwrap();
    let _session = mount(source.path(), mountpoint.path()).unwrap();

    let mnt_a = mountpoint.path().join("a.conf");
    let mnt_b = mountpoint.path().join("b.conf");
    let ino_a = fs::metadata(&mnt_a).unwrap().ino();
    let ino_b = fs::metadata(&mnt_b).unwrap().ino();
    // Hard-linked aliases must not be collapsed into one overlay inode —
    // that is what lets them carry independent SELinux labels.
    assert_ne!(ino_a, ino_b);
    // Reading through both paths yields the same (shared) content.
    assert_eq!(fs::read(&mnt_a).unwrap(), b"shared-content\n");
    assert_eq!(fs::read(&mnt_b).unwrap(), b"shared-content\n");

    // Each path owns its xattr space even though they share a backing inode.
    sys_setxattr(&mnt_a, "user.color", b"red", 0).unwrap();
    sys_setxattr(&mnt_b, "user.color", b"blue", 0).unwrap();
    assert_eq!(sys_getxattr(&mnt_a, "user.color").unwrap(), b"red");
    assert_eq!(sys_getxattr(&mnt_b, "user.color").unwrap(), b"blue");

    // The shared backing inode is never written through the overlay.
    assert!(sys_listxattr(&a_path).unwrap().is_empty());
    assert!(sys_listxattr(&b_path).unwrap().is_empty());
}

#[test]
fn source_requires_an_existing_directory() {
    let root = TempDir::new().unwrap();

    let ok = MetaFs::new(&root.path().join("does-not-exist"));
    assert!(ok.is_err());

    let file = root.path().join("file.txt");
    fs::write(&file, b"x").unwrap();
    assert!(MetaFs::new(&file).is_err());

    assert!(MetaFs::new(root.path()).is_ok());
}

#[test]
fn non_utf8_file_names_pass_through() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse unavailable");
        return;
    }

    let source = TempDir::new().unwrap();
    let weird = PathBuf::from(std::ffi::OsString::from_vec(b"we\xffird".to_vec()));
    fs::write(source.path().join(&weird), b"data").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let _session = mount(source.path(), mountpoint.path()).unwrap();

    assert_eq!(fs::read(mountpoint.path().join(&weird)).unwrap(), b"data");
    let names: Vec<PathBuf> = fs::read_dir(mountpoint.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into())
        .collect();
    assert!(names.iter().any(|n| n == &weird));
}
