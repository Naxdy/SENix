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
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

use clap::Parser;
use fuser::{Config, MountOption, Session, SessionACL};
use log::{Metadata, Record, debug};
use metafs::fs::MetaFs;

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

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    install_signal_handlers();
    mark_survivor();
    let config = session_config(&cli.options, cli.read_only, cli.read_write);

    let result = if cli.foreground {
        mount_foreground(&source, &cli.mountpoint, &config)
    } else {
        mount_daemonized(&source, &cli.mountpoint, &config)
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
fn session_config(forwarded: &[String], read_only: bool, read_write: bool) -> Config {
    let mut config = Config::default();
    config
        .mount_options
        .push(MountOption::FSName("metafs".to_string()));
    config
        .mount_options
        .push(MountOption::Subtype("metafs".to_string()));

    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .min(16);
    config.n_threads = Some(threads);
    #[cfg(target_os = "linux")]
    {
        config.clone_fd = threads > 1;
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
        _ => debug!("ignoring unrecognized mount option {option:?}"),
    }
}

/// Mount and serve in the calling process (blocking until unmount).
fn mount_foreground(source: &Path, mountpoint: &Path, config: &Config) -> io::Result<()> {
    let fs = MetaFs::new(source)?;
    let requests = fs.requests();
    let session = Session::new(fs, mountpoint, config)?;
    write_kmsg(&format!("metafs: mounted at {}", mountpoint.display()));
    spawn_heartbeat(requests, mountpoint.to_path_buf());
    log::info!("metafs: mounted at {}, serving", mountpoint.display());
    let result = session.run();
    write_kmsg("metafs: session ended");
    log::info!("metafs: session ended");
    result
}

/// Mount in a forked, detached process, returning to the caller only once the
/// filesystem is attached (or reporting the mount error).
///
/// `mount(8)` invokes the FUSE helper and waits for it to exit, so a
/// foreground daemon would hang the mount command. We instead fork, let the
/// child attach the filesystem, and exit the parent with success only after
/// the child signals that the mount is live. The child redirects its standard
/// streams and serves requests until unmounted.
fn mount_daemonized(source: &Path, mountpoint: &Path, config: &Config) -> io::Result<()> {
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
            let mut ready = File::from(write);

            let session =
                match MetaFs::new(source).and_then(|fs| Session::new(fs, mountpoint, config)) {
                    Ok(session) => {
                        // Mount attached: report success to the parent, detach
                        // from the caller's streams, then serve requests.
                        drop(ready);
                        detach_stdio();
                        session
                    }
                    Err(e) => {
                        let _ = writeln!(ready, "{e}");
                        drop(ready);
                        std::process::exit(1);
                    }
                };
            let result = session.run();
            std::process::exit(i32::from(result.is_err()));
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

/// File descriptor for `/dev/kmsg`, opened once at startup and reused from
/// within signal handlers (where allocating / opening is risky).
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

/// Open `/dev/kmsg` once so later (including signal-handler) writes cannot
/// fail on descriptor exhaustion.
fn open_kmsg() {
    // SAFETY: constant arguments, path is NUL-terminated.
    let fd = unsafe { libc::open(c"/dev/kmsg".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    KMSG_FD.store(fd, Ordering::Relaxed);
}

/// Signal handler: log the signal and continue (the daemon only exits when
/// its FUSE connection ends). Kept async-signal-safe: no allocation, direct
/// `write(2)` to the pre-opened kmsg descriptor.
extern "C" fn on_term_signal(_sig: libc::c_int) {
    let fd = KMSG_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        const MSG: &[u8] = b"<6>metafs: caught termination signal, staying alive\n";
        // SAFETY: static buffer, valid fd.
        unsafe {
            libc::write(fd, MSG.as_ptr().cast(), MSG.len());
        }
    }
}

/// Report periodic diagnostics to the kernel log.
fn spawn_heartbeat(requests: std::sync::Arc<AtomicU64>, mountpoint: PathBuf) {
    static DUMPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    std::thread::spawn(move || {
        let pid = std::process::id();
        loop {
            let store = store_mounts_summary();
            // `.` is the CWD, which the daemon anchors to the backing store.
            let backing_desc = match std::fs::read_dir(".") {
                Ok(rd) => format!("entries={}", rd.count()),
                Err(e) => format!("error={e}"),
            };
            if store.is_empty() && !DUMPED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                // Something tectonic happened to the mount table (e.g. the
                // initrd root switch); dump it once, then stay quiet.
                for (mnt, fstype) in mountinfo_entries() {
                    write_kmsg(&format!("metafs mounts {pid}: {mnt} ({fstype})"));
                }
                write_kmsg(&format!(
                    "metafs probes {pid}: {}",
                    match std::fs::read_to_string("/proc/self/mountinfo") {
                        Ok(s) => format!("mountinfo ok:{}lines", s.lines().count()),
                        Err(e) => format!("mountinfo err:{e}"),
                    }
                ));
                write_kmsg("metafs mounts: end");
            }
            write_kmsg(&format!(
                "metafs heartbeat pid={pid}: last_op={} survivor={} fuse={:?} store_mounts=<{}> mountpoint={} backing={backing_desc} requests={}",
                metafs::fs::last_op(),
                survivor_xattr(),
                fuse_mountpoint(),
                store.join(" "),
                mountpoint.display(),
                requests.load(std::sync::atomic::Ordering::Relaxed),
            ));
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

/// Ask systemd to keep this daemon across the switch-root killing spree by
/// setting the same cgroup xattr systemd itself would set for
/// `SurviveFinalKillSignal=yes` (see `systemd.io/ROOT_STORAGE_DAEMONS`). This is
/// belt-and-suspenders in case systemd has not (yet) applied it to our unit.
fn mark_survivor() {
    let Some(path) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|cg| {
            cg.lines()
                .next()
                .and_then(|l| l.split_once(':').map(|(_, p)| p.trim().to_string()))
        })
    else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let cgpath = std::ffi::CString::new(format!("/sys/fs/cgroup{path}")).unwrap_or_default();
    let mut name = b"user.survive_final_kill_signal".to_vec();
    name.push(0);
    let mut value = b"1".to_vec();
    value.push(0);
    // SAFETY: the three pointers reference valid, NUL-terminated buffers;
    // `setxattr` cannot fail dangerously (the error is only reported).
    let r = unsafe {
        libc::setxattr(
            cgpath.as_ptr(),
            name.as_ptr().cast(),
            value.as_ptr().cast(),
            1,
            0,
        )
    };
    write_kmsg(if r == 0 {
        "metafs: survivor cgroup xattr applied"
    } else {
        "metafs: survivor cgroup xattr failed (best effort)"
    });
}

/// Whether the current process's cgroup carries the
/// `user.survive_final_kill_signal` xattr (i.e. whether systemd's
/// switch-root killing spree will spare it).
fn survivor_xattr() -> bool {
    let Some(path) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|cg| {
            cg.lines()
                .next()
                .and_then(|l| l.split_once(':').map(|(_, p)| p.trim().to_string()))
        })
    else {
        return false;
    };
    if path.is_empty() {
        return false;
    }
    let cgpath = std::ffi::CString::new(format!("/sys/fs/cgroup{path}")).unwrap_or_default();
    let mut name = b"user.survive_final_kill_signal".to_vec();
    name.push(0);
    // SAFETY: pointers reference valid buffers; a positive return means the
    // attribute exists.
    let mut value = [0u8; 16];
    unsafe {
        libc::getxattr(
            cgpath.as_ptr(),
            name.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        ) > 0
    }
}

/// Ignore `SIGTERM`/`SIGHUP` so the daemon survives systemd's switch-root and
/// shutdown killing sprees (see `systemd.io/ROOT_STORAGE_DAEMONS`): the daemon
/// only exits when the mounted filesystem is unmounted, which ends the FUSE
/// connection and makes `Session::run` return.
fn install_signal_handlers() {
    open_kmsg();
    // SAFETY: `sigaction` with a constant handler function, an empty signal
    // mask and SA_RESTART (so syscalls are not interrupted with EINTR).
    #[allow(clippy::borrow_as_ptr)]
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let handler: unsafe extern "C" fn(libc::c_int) = on_term_signal;
        action.sa_sigaction = handler as libc::sighandler_t;
        libc::sigemptyset(&raw mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &raw const action, std::ptr::null_mut());
    }
}

/// Scan `/proc/self/mountinfo` for a `fuse.metafs` mount and return its
/// mountpoint, if present.
fn fuse_mountpoint() -> Option<String> {
    mountinfo_entries()
        .iter()
        .find(|(_mnt, fstype)| fstype == "fuse.metafs")
        .map(|(mnt, _)| mnt.clone())
}

/// Return a short summary of mounts under `/nix` (or the initrd's `/sysroot`
/// variant), to reveal whether the store stack survived a root switch.
fn store_mounts_summary() -> Vec<String> {
    mountinfo_entries()
        .into_iter()
        .filter(|(mnt, _)| mnt.starts_with("/nix") || mnt.starts_with("/sysroot/nix"))
        .map(|(mnt, fstype)| format!("{mnt}:{fstype}"))
        .collect()
}

/// Parse `/proc/self/mountinfo` into (mountpoint, fstype) pairs.
fn mountinfo_entries() -> Vec<(String, String)> {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    info.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let fs = line.split(" - ").nth(1)?;
            let fstype = fs.split(' ').next()?;
            Some((fields.get(4)?.to_string(), fstype.to_string()))
        })
        .collect()
}
