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

use clap::Parser;
use fuser::{Config, MountOption, Session, SessionACL};
use log::debug;
use metafs::fs::MetaFs;

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

    let level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
    if let Some(fstype) = &cli.fstype {
        debug!("mount(8) forwarded filesystem type {fstype:?}");
    }
    if cli.no_mtab {
        debug!("mount(8) forwarded -n (no /etc/mtab update)");
    }

    let source = strip_type_prefix(&cli.source);
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
    let session = Session::new(fs, mountpoint, config)?;
    session.run()
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
