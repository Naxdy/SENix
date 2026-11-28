//! Command-line entry point: mount the pass-through filesystem.
//!
//! `metafs` is both the FUSE daemon and the `mount(8)` helper for the
//! `fuse.metafs` filesystem type (the package installs a `mount.fuse.metafs`
//! alias for this binary). It therefore understands the arguments mount(8)
//! forwards to mount helpers in addition to its own flags. Mounting through
//! `mount(8)` — e.g. from `/etc/fstab` — is the primary, supported way of
//! using this filesystem.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

use clap::Parser;
use fuser::{Config, MountOption, Session, SessionACL};
use log::{Metadata, Record, debug};
use metafs::fs::MetaFs;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A `log` backend that writes every record to `/dev/kmsg` through the held
/// descriptor, so daemon and fuser diagnostics remain visible on the console
/// even after journald stops at the initrd root switch.
struct KmsgLogger;

impl log::Log for KmsgLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            write_kmsg(&format!("metafs[{}]: {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

static KMSG_LOGGER: KmsgLogger = KmsgLogger;

/// Report panics (e.g. a stuck request worker) to the kernel log; the default
/// panic hook would only reach stderr, which is detached/invisible here.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write_kmsg(&format!("metafs: worker panicked: {info}"));
        default(info);
    }));
}

/// Mount an existing directory as a strictly read-only FUSE overlay.
///
/// Every mutation returns `EROFS`, while extended attributes are kept in an
/// in-memory map so the backing filesystem is never written to. The source
/// directory may be the same path as the mountpoint.
///
/// When invoked by `mount(8)` as the `mount.fuse.metafs` helper, the hidden
/// `-t`, `-o`, `-n`, `-r` and `-w` options are accepted for compatibility.
#[derive(Parser)]
#[command(name = "metafs", version, about)]
// The extra booleans exist solely to tolerate flags that mount(8) forwards to
// mount helpers; folding them into a single flags value would obscure the CLI.
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// Directory on an already-mounted filesystem to expose.
    source: PathBuf,

    /// Directory onto which the read-only overlay is mounted.
    mountpoint: PathBuf,

    /// Stay in the foreground instead of forking into the background.
    ///
    /// Use this when running under a supervisor such as systemd so the
    /// daemon's standard streams stay attached, or to see mount errors
    /// directly. Without it the process detaches and `mount(8)` returns as
    /// soon as the filesystem is attached.
    #[arg(short = 'f', long)]
    foreground: bool,

    /// Mount options (from `/etc/fstab` or the `mount(8)` command line).
    ///
    /// Recognized options are honored (e.g. `default_permissions`,
    /// `allow_other`, `nodev`, `nosuid`); unknown ones are ignored.
    #[arg(short = 'o', value_name = "OPTS")]
    options: Vec<String>,

    /// Enable debug logging.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Mark the mount as an `SELinux` label source (`seclabel`).
    ///
    /// `SELinux` routes `security.selinux` xattr operations to the filesystem
    /// only when the superblock is marked label-bearing (`SBLABEL_MNT`);
    /// without it `selinux_inode_setxattr` short-circuits with `EOPNOTSUPP`
    /// before a request ever reaches the daemon. Only meaningful on systems
    /// where the `SELinux` `LSM` is active (the kernel rejects the option on
    /// others), so it is opt-in.
    #[arg(long)]
    seclabel: bool,

    /// Accepted for compatibility with mount(8) helpers; the filesystem type
    /// is implied by the helper name.
    #[arg(short = 't', value_name = "TYPE", hide = true)]
    fstype: Option<String>,

    /// Accepted for compatibility with mount(8) helpers; /etc/mtab is managed
    /// by mount(8) itself.
    #[arg(short = 'n', hide = true)]
    no_mtab: bool,

    /// Read-only mount (equivalent to the `ro` mount option).
    #[arg(short = 'r', hide = true)]
    read_only: bool,

    /// Read-write mount (equivalent to the `rw` mount option).
    #[arg(short = 'w', hide = true)]
    read_write: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    open_kmsg();
    install_panic_hook();
    // Log through /dev/kmsg using a held descriptor: journald stops at the
    // initrd root switch, so stderr-based logging would be invisible in a
    // frozen or hung boot, whereas kernel messages always reach the console.
    log::set_logger(&KMSG_LOGGER).expect("logger set");
    log::set_max_level(if cli.verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Info
    });
    if let Some(fstype) = &cli.fstype {
        debug!("mount(8) forwarded filesystem type {fstype:?}");
    }
    if cli.no_mtab {
        debug!("mount(8) forwarded -n (no /etc/mtab update)");
    }

    let source = strip_type_prefix(&cli.source);
    let config = session_config(&cli.options, cli.read_only, cli.read_write, cli.seclabel);

    let result = if cli.foreground {
        mount_foreground(&source, &cli.mountpoint, &config, cli.seclabel)
    } else {
        mount_daemonized(&source, &cli.mountpoint, &config, cli.seclabel)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("metafs: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Strip a leading `metafs#` prefix from a fstab-style source.
///
/// The `mount.fuse` helper splits `type#source` itself only when no `-t` was
/// given; with `-t fuse.metafs` the raw value reaches the daemon untouched.
fn strip_type_prefix(source: &Path) -> PathBuf {
    const PREFIX: &[u8] = b"metafs#";
    let bytes = source.as_os_str().as_bytes();
    if bytes.starts_with(PREFIX) {
        PathBuf::from(OsString::from_vec(bytes[PREFIX.len()..].to_vec()))
    } else {
        source.to_path_buf()
    }
}

/// Build the session configuration, honoring mount options plus the read-only
/// / read-write switch.
#[allow(clippy::too_many_lines)]
fn session_config(
    forwarded: &[String],
    read_only: bool,
    read_write: bool,
    seclabel: bool,
) -> Config {
    let mut config = Config::default();
    config
        .mount_options
        .push(MountOption::FSName("metafs".to_string()));
    config
        .mount_options
        .push(MountOption::Subtype("metafs".to_string()));
    // Let the kernel enforce permissions itself from the (faithful) modes we
    // report; the backing filesystem is immutable, so its permission bits are
    // exactly what should govern access. This also avoids every `access(2)`
    // round-tripping to the daemon.
    config.mount_options.push(MountOption::DefaultPermissions);
    // The kernel's `fuse_permission` denies access with EACCES to processes
    // that are neither the mount owner nor covered by `allow_other`/`allow_root`
    // (see `fuse_allow_current_process()`). The overlay serves the whole system
    // as its store, so every process — including services running under
    // dedicated users such as dbus or systemd-network — must be able to read
    // and execute the underlying files. Default to allow_other; the `-o`
    // options can still request `allow_root` explicitly.
    config.acl = SessionACL::All;

    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .min(16);
    config.n_threads = Some(threads);
    #[cfg(target_os = "linux")]
    {
        config.clone_fd = false;
    }

    if read_only {
        config.mount_options.push(MountOption::RO);
    }
    if read_write {
        config.mount_options.push(MountOption::RW);
    }

    for options in forwarded {
        for option in options.split(',') {
            translate_mount_option(&mut config, option);
        }
    }

    if seclabel {
        // SELinux routes `security.selinux` xattr operations to the backing
        // filesystem only when the superblock is labeled (`SBLABEL_MNT`); the
        // `seclabel` mount flag sets it and the kernel rejects the option on
        // non-SELinux systems, so it is only added on request.
        config
            .mount_options
            .push(MountOption::CUSTOM("seclabel".to_string()));
    }

    config
}

/// Translate one comma-separated mount option into the session configuration.
fn translate_mount_option(config: &mut Config, option: &str) {
    match option {
        "default_permissions" => config.mount_options.push(MountOption::DefaultPermissions),
        "dev" => config.mount_options.push(MountOption::Dev),
        "nodev" => config.mount_options.push(MountOption::NoDev),
        "suid" => config.mount_options.push(MountOption::Suid),
        "nosuid" => config.mount_options.push(MountOption::NoSuid),
        "ro" => config.mount_options.push(MountOption::RO),
        "rw" => config.mount_options.push(MountOption::RW),
        "allow_other" => config.acl = SessionACL::All,
        "allow_root" => config.acl = SessionACL::RootAndOwner,
        // SELinux label source flag; see `session_config`.
        "seclabel" => config
            .mount_options
            .push(MountOption::CUSTOM("seclabel".to_string())),
        // SELinux mount-context options are meaningful (e.g. as the boot-time
        // store's superblock context) and must reach the kernel verbatim.
        // `fscontext=`/`context=` only set labels; they do not turn off xattr
        // labeling (which `fs_use_xattr fuse` supplies), so forwarding is safe.
        o if o.starts_with("context=")
            || o.starts_with("fscontext=")
            || o.starts_with("defcontext=")
            || o.starts_with("rootcontext=") =>
        {
            config
                .mount_options
                .push(MountOption::CUSTOM(o.to_string()));
        }
        _ => debug!("ignoring unrecognized mount option {option:?}"),
    }
}

/// Mount and serve in the calling process (blocking until unmount).
fn mount_foreground(
    source: &Path,
    mountpoint: &Path,
    config: &Config,
    seclabel: bool,
) -> io::Result<()> {
    let fs = MetaFs::new(source)?;
    write_kmsg(&format!("metafs: mounting {}", mountpoint.display()));
    let result = serve_filesystem(fs, mountpoint, config, seclabel, || Ok(()));
    write_kmsg(&format!(
        "metafs: {}",
        if result.is_ok() {
            "session ended"
        } else {
            "session ended with error"
        }
    ));
    result
}

/// Create a session and serve until unmounted.
///
/// With `--seclabel`, the `SELinux` policy declares fuse `fs_use_xattr`, so the
/// kernel probes `security.selinux` on the root inode synchronously inside
/// `mount(2)` (`sb_check_xattr_support`). That probe must be answered by the
/// daemon, but a daemon blocked inside its own `mount()` can never answer it.
/// We therefore start the request loop in a helper thread via
/// [`Session::from_fd`] (which never mounts) and perform `mount(2)` from the
/// calling thread, so every mount-time request is serviced the moment it is
/// queued. `before_serve` (e.g. the daemonized readiness handshake) runs once
/// the filesystem is attached.
fn serve_filesystem(
    fs: MetaFs,
    mountpoint: &Path,
    config: &Config,
    seclabel: bool,
    before_serve: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if !seclabel {
        // fuser's own mount path, untouched for non-SELinux use (e.g. the
        // plain metafs VM test): no policy probe is issued, so no deadlock.
        let session = Session::new(fs, mountpoint, config)?;
        log::info!("metafs: mounted at {}, serving", mountpoint.display());
        return before_serve().and_then(|()| session.run());
    }

    let fuse = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .map_err(|e| io::Error::new(e.kind(), format!("open /dev/fuse: {e}")))?;
    let data = fuse_mount_data(fuse.as_raw_fd(), mountpoint, "seclabel")?;
    let target = mountpoint.to_path_buf();
    let config = config.clone();

    let handle = std::thread::spawn(move || -> io::Result<()> {
        let session = Session::from_fd(fs, fuse.into(), config.acl, config.clone())?;
        let result = session.run();
        // `from_fd` does not unmount on drop; detach so the mount never leaks
        // (best effort — the caller may have already unmounted).
        let _ = nix::mount::umount2(&target, nix::mount::MntFlags::MNT_DETACH);
        result
    });

    let flags = nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV;
    nix::mount::mount(
        Some("metafs"),
        mountpoint,
        Some("fuse"),
        flags,
        Some(data.as_str()),
    )
    .map_err(errno)?;
    log::info!("metafs: mounted {} data={data}", mountpoint.display());

    before_serve()?;
    handle.join().unwrap_or(Ok(()))
}

/// Build the mount(2) data for a FUSE mount: the device descriptor and
/// `rootmode` plus the access/label options. `extra` is appended verbatim so
/// the caller can request `SELinux` labeling.
fn fuse_mount_data(
    fd: std::os::unix::io::RawFd,
    mountpoint: &Path,
    extra: &str,
) -> io::Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let rootmode = std::fs::metadata(mountpoint)?.permissions().mode() & libc::S_IFMT;
    Ok(format!(
        "fd={fd},rootmode={rootmode:o},user_id=0,group_id=0,default_permissions,allow_other,{extra}"
    ))
}

fn mount_daemonized(
    source: &Path,
    mountpoint: &Path,
    config: &Config,
    seclabel: bool,
) -> io::Result<()> {
    let (read, write) = nix::unistd::pipe().map_err(errno)?;
    // SAFETY: `fork` is safe to call as long as the program does not rely on
    // atfork handlers for correctness, which none of our dependencies do.
    let fork = unsafe { nix::unistd::fork() }.map_err(errno)?;
    match fork {
        nix::unistd::ForkResult::Parent { .. } => {
            drop(write);
            let mut reader = File::from(read);
            let mut message = String::new();
            // Blocks until the child closes the pipe, i.e. once the mount is
            // attached or has failed.
            reader.read_to_string(&mut message)?;
            if message.trim().is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(message.trim().to_string()))
            }
        }
        nix::unistd::ForkResult::Child => {
            drop(read);
            let _ = nix::unistd::setsid();
            // Single ownership of the readiness pipe write end; `take()` moves
            // it out exactly once on whichever path runs, so the parent always
            // sees EOF (success) or the error text. A stray held-open write
            // end would block `mount(8)` forever.
            let mut ready: Option<File> = Some(File::from(write));

            let result = MetaFs::new(source).and_then(|fs| {
                // Mount attached: report success to the parent, detach from the
                // caller's streams, then serve requests.
                let signal_ready = || {
                    drop(ready.take());
                    detach_stdio();
                    Ok(())
                };
                serve_filesystem(fs, mountpoint, config, seclabel, signal_ready)
            });
            match result {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    if let Some(mut r) = ready.take() {
                        let _ = writeln!(r, "{e}");
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Redirect the daemon's standard streams to `/dev/null`.
fn detach_stdio() {
    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let fd = null.as_raw_fd();
        // SAFETY: `fd` refers to a valid, open descriptor of `/dev/null`; the
        // returned descriptor numbers 0..=2 are legal targets for `dup2`.
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}

fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// File descriptor for `/dev/kmsg`, opened once at startup and reused by every
/// later write, so a diagnostic never has to open a descriptor itself.
static KMSG_FD: AtomicI32 = AtomicI32::new(-1);

/// Write a message to the kernel log.
///
/// Kernel messages are forwarded to the consoles, so they reach the captured
/// serial boot log even after journald stops at the initrd root switch. Used
/// for diagnostics of the switch-root transition.
fn write_kmsg(msg: &str) {
    let fd = KMSG_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    // Include the syslog-info level prefix "<6>" and a trailing newline; the
    // kernel timestamp/prefixing is done by the kmsg device itself.
    let mut buf = String::with_capacity(msg.len() + 8);
    buf.push_str("<6>");
    buf.push_str(msg);
    buf.push('\n');
    // SAFETY: `fd` is an open writable descriptor; the buffer is valid for the
    // length given. `write(2)` is async-signal-safe.
    unsafe {
        libc::write(fd, buf.as_ptr().cast(), buf.len());
    }
}

/// Open `/dev/kmsg` once so later diagnostics cannot fail on descriptor
/// exhaustion.
fn open_kmsg() {
    // SAFETY: constant arguments, path is NUL-terminated.
    let fd = unsafe { libc::open(c"/dev/kmsg".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    KMSG_FD.store(fd, Ordering::Relaxed);
}
