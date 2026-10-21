//! Command line interface definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// A Windows DLL injector built on top of `dll_syringe`.
#[derive(Debug, Parser)]
#[command(name = "wdi", version, about, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inject a DLL into a running process
    Inject(InjectArgs),
    /// Eject a DLL that is loaded in a running process
    Eject(EjectArgs),
    /// List running processes
    List(ListArgs),
    /// Launch a process and inject a DLL into it (suspended injection)
    Spawn(SpawnArgs),
}

/// Options for selecting a target process.
#[derive(Debug, Clone, Args)]
pub struct TargetArgs {
    /// Target process id
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pub pid: Option<u32>,

    /// Target process name (case-insensitive, matches a substring)
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub name: Option<String>,

    /// If several processes match `--name`, pick the first one instead of failing
    #[arg(long)]
    pub first: bool,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    /// Path to the DLL to inject
    #[arg(value_name = "DLL")]
    pub dll: PathBuf,

    #[command(flatten)]
    pub target: TargetArgs,

    /// Do nothing if the DLL is already loaded in the target process
    #[arg(long)]
    pub if_missing: bool,

    /// Map the DLL into memory without LoadLibrary (reflective loading)
    ///
    /// The module is not registered in the target's PEB module list, so it
    /// cannot be found with `list`/`eject` afterwards.
    #[arg(long)]
    pub reflective: bool,
}

#[derive(Debug, Args)]
pub struct EjectArgs {
    /// Path (or file name) of the DLL to eject
    #[arg(value_name = "DLL")]
    pub dll: PathBuf,

    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Only show processes whose name contains this string
    #[arg(short = 'f', long, value_name = "SUBSTR")]
    pub filter: Option<String>,

    /// Also print the full executable path
    #[arg(long)]
    pub paths: bool,
}

#[derive(Debug, Args)]
pub struct SpawnArgs {
    /// Path to the executable to launch
    #[arg(value_name = "EXE")]
    pub exe: PathBuf,

    /// DLL to inject into the new process
    #[arg(short = 'd', long = "dll", value_name = "DLL")]
    pub dll: Option<PathBuf>,

    /// Argument to pass to the executable (may be repeated)
    #[arg(
        short = 'a',
        long = "arg",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,

    /// Create the process without suspending it (inject after it has started)
    #[arg(long)]
    pub unsuspended: bool,

    /// Wait for the process to exit and report its exit code
    #[arg(short = 'w', long)]
    pub wait: bool,

    /// Map the DLL into memory without LoadLibrary (reflective loading)
    ///
    /// The module is not registered in the target's PEB module list, so it
    /// cannot be found with `list`/`eject` afterwards.
    #[arg(long)]
    pub reflective: bool,
}
