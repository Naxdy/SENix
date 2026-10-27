//! `sepol2nix` command line front end.
//!
//! For now it parses one `SELinux` policy source file into its typed syntax tree
//! and reports the result. Translation to Nix is not implemented yet.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Parser as ClapParser, Subcommand, ValueEnum};
use sepol2nix::cil::CilFile;
use sepol2nix::file_context::FileContextFile;
use sepol2nix::interface::InterfaceFile;
use sepol2nix::m4::M4File;
use sepol2nix::metadata::LayerMetadata;
use sepol2nix::nix::AsNixExpr;
use sepol2nix::type_enforcement::TypeEnforcementFile;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(ClapParser, Debug)]
#[command(about = "Parse a SELinux policy source file into a typed syntax tree")]
struct Cli {
    /// Treat an unrecognized file name as a failure.
    #[arg(long, global = true)]
    strict: bool,

    /// Override the dialect instead of deriving it from the file name.
    #[arg(long, global = true, value_enum)]
    dialect: Option<Dialect>,

    #[command(subcommand)]
    command: Command,
}

/// The output format and its input file.
#[derive(Subcommand, Debug)]
enum Command {
    /// Print a one-line summary of the parsed file.
    Summary {
        /// The policy source file to parse.
        path: PathBuf,
    },

    /// Print the parsed syntax tree.
    Tree {
        /// The policy source file to parse.
        path: PathBuf,
    },

    /// Print the file as a Nix expression.
    ///
    /// `/usr` file-context rules are emitted commented; `--substitute-usr`
    /// additionally emits live rules where `/usr` is replaced by the given
    /// prefix (repeatable).
    Nix {
        /// The policy source file to parse.
        path: PathBuf,

        /// Additional live spelling for the commented `/usr` rules.
        #[arg(long, value_enum)]
        substitute_usr: Vec<CliUsrSubstitution>,
    },
}

impl Command {
    fn path(&self) -> &Path {
        match self {
            Self::Summary { path } | Self::Tree { path } | Self::Nix { path, .. } => path,
        }
    }
}

/// Where to additionally emit the commented `/usr` rules.
#[derive(ValueEnum, Clone, Copy, Debug)]
enum CliUsrSubstitution {
    /// Emit `@systemPath@`-prefixed rules.
    SystemPath,
    /// Emit `/nix/store/[^/]+`-prefixed rules.
    NixStore,
}

impl From<CliUsrSubstitution> for sepol2nix::nix::UsrSubstitution {
    fn from(value: CliUsrSubstitution) -> Self {
        match value {
            CliUsrSubstitution::SystemPath => Self::SystemPath,
            CliUsrSubstitution::NixStore => Self::NixStore,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Dialect {
    Te,
    If,
    Fc,
    Cil,
    M4,
    Metadata,
}

fn dialect_for(path: &Path) -> Option<Dialect> {
    let name = path.file_name()?.to_str()?;
    if name == "metadata.xml" {
        return Some(Dialect::Metadata);
    }
    match name {
        "constraints"
        | "context_defaults"
        | "global_booleans"
        | "global_tunables"
        | "mcs"
        | "mls"
        | "policy_capabilities"
        | "users"
        | "access_vectors"
        | "initial_sids"
        | "security_classes" => return Some(Dialect::Te),
        _ => {}
    }
    match path.extension()?.to_str()? {
        "te" => Some(Dialect::Te),
        "if" => Some(Dialect::If),
        "fc" => Some(Dialect::Fc),
        "cil" => Some(Dialect::Cil),
        "spt" | "m4" => Some(Dialect::M4),
        "in" => match path.file_stem()?.to_str()?.rsplit_once('.') {
            Some((_, "te")) => Some(Dialect::Te),
            Some((_, "if")) => Some(Dialect::If),
            _ => None,
        },
        _ => None,
    }
}

/// A parsed policy source.
enum Parsed {
    Te(TypeEnforcementFile),
    If(InterfaceFile),
    Fc(FileContextFile),
    Cil(CilFile),
    M4(M4File),
    Metadata(LayerMetadata),
}

impl Parsed {
    fn parse(source: &str, dialect: Dialect) -> sepol2nix::error::Result<Self> {
        Ok(match dialect {
            Dialect::Te => Self::Te(TypeEnforcementFile::from_str(source)?),
            Dialect::If => Self::If(InterfaceFile::from_str(source)?),
            Dialect::Fc => Self::Fc(FileContextFile::from_str(source)?),
            Dialect::Cil => Self::Cil(CilFile::from_str(source)?),
            Dialect::M4 => Self::M4(M4File::from_str(source)?),
            Dialect::Metadata => Self::Metadata(LayerMetadata::from_str(source)?),
        })
    }

    fn summary(&self) -> String {
        match self {
            Self::Te(file) => format!(
                "{} statements{}",
                file.statements.statements().len(),
                file.module
                    .as_ref()
                    .map(|module| format!(", module {}", module.name))
                    .unwrap_or_default()
            ),
            Self::If(file) => format!("{} macros", file.declarations.len()),
            Self::Fc(file) => format!("{} items", file.items().len()),
            Self::Cil(file) => format!("{} statements", file.statements().len()),
            Self::M4(file) => format!("{} items", file.items().len()),
            Self::Metadata(_) => "layer metadata".to_owned(),
        }
    }

    fn tree(&self) -> String {
        match self {
            Self::Te(value) => format!("{value:#?}"),
            Self::If(value) => format!("{value:#?}"),
            Self::Fc(value) => format!("{value:#?}"),
            Self::Cil(value) => format!("{value:#?}"),
            Self::M4(value) => format!("{value:#?}"),
            Self::Metadata(value) => format!("{value:#?}"),
        }
    }

    fn nix(
        &self,
        substitute_usr: &[sepol2nix::nix::UsrSubstitution],
    ) -> sepol2nix::error::Result<String> {
        match self {
            Self::Te(value) => Ok(value.to_nix_string()?),
            Self::If(value) => Ok(value.to_nix_string()?),
            Self::Fc(value) => {
                let mut out = String::new();
                let mut nix = sepol2nix::nix::NixWriter::new(&mut out);
                value.write_nix_with_options(
                    &mut nix,
                    &sepol2nix::nix::FileContextOptions {
                        substitute_usr: substitute_usr.to_vec(),
                    },
                )?;
                Ok(out)
            }
            Self::Cil(value) => Ok(value.to_nix_string()?),
            Self::M4(value) => Ok(value.to_nix_string()?),
            Self::Metadata(value) => Ok(value.to_nix_string()?),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let path = cli.command.path();

    if path.is_dir() {
        eprintln!("{}: is a directory, expected a file", path.display());
        return ExitCode::FAILURE;
    }

    let Some(dialect) = cli.dialect.or_else(|| dialect_for(path)) else {
        eprintln!("{}: unrecognized policy source", path.display());
        return if cli.strict {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    };

    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };

    match Parsed::parse(&source, dialect) {
        Ok(parsed) => {
            match &cli.command {
                Command::Summary { .. } => println!("{}: {}", path.display(), parsed.summary()),
                Command::Tree { .. } => {
                    println!("### {}", path.display());
                    println!("{}", parsed.tree());
                }
                Command::Nix { substitute_usr, .. } => {
                    let substitutions: Vec<_> =
                        substitute_usr.iter().copied().map(Into::into).collect();
                    match parsed.nix(&substitutions) {
                        Ok(expression) => print!("{expression}"),
                        Err(error) => {
                            eprintln!("{}: {error}", path.display());
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}
