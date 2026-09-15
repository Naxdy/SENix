//! Command-line entry point: mount the pass-through filesystem.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use metafs::fs::MetaFs;

/// Mount an existing directory as a strictly read-only FUSE overlay.
///
/// Every mutation returns `EROFS`, while extended attributes are kept in an
/// in-memory map so the backing filesystem is never written to. The source
/// directory may be the same path as the mountpoint.
#[derive(Parser)]
#[command(name = "metafs", version, about)]
struct Cli {
    /// Directory on an already-mounted filesystem to expose.
    source: PathBuf,

    /// Directory onto which the read-only overlay is mounted.
    mountpoint: PathBuf,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let config = session_config();
    match MetaFs::new(&cli.source).and_then(|fs| fuser::mount(fs, &cli.mountpoint, &config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("metafs: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Session configuration: a purely-read-only mount request, multiple worker
/// threads for concurrent requests, and a stable filesystem name.
fn session_config() -> fuser::Config {
    let mut config = fuser::Config::default();
    config
        .mount_options
        .push(fuser::MountOption::FSName("metafs".to_string()));
    config
        .mount_options
        .push(fuser::MountOption::Subtype("metafs".to_string()));

    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .min(16);
    config.n_threads = Some(threads);
    #[cfg(target_os = "linux")]
    {
        config.clone_fd = threads > 1;
    }
    config
}
