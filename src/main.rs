mod cli;

#[cfg(windows)]
mod commands;
#[cfg(windows)]
mod reflective;
#[cfg(windows)]
mod target;
#[cfg(windows)]
mod util;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run(cli: Cli) -> anyhow::Result<()> {
    use cli::Command;

    match cli.command {
        Command::Inject(args) => commands::inject::run(args),
        Command::Eject(args) => commands::eject::run(args),
        Command::List(args) => commands::list::run(args),
        Command::Spawn(args) => commands::spawn::run(args),
    }
}

#[cfg(not(windows))]
fn run(_cli: Cli) -> anyhow::Result<()> {
    anyhow::bail!("wdi only supports Windows (dll_syringe is Windows-only)")
}
