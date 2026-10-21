//! Resolving the target process from CLI arguments.

use std::path::Path;

use anyhow::{Context, Result, bail};
use dll_syringe::process::{BorrowedProcess, BorrowedProcessModule, OwnedProcess, Process};

use crate::cli::TargetArgs;

/// Resolves a target process from `--pid` / `--name`.
pub fn resolve(target: &TargetArgs) -> Result<OwnedProcess> {
    match (target.pid, target.name.as_deref()) {
        (Some(_), Some(_)) => bail!("provide either --pid or --name, not both"),
        (None, None) => bail!("no target given: pass --pid <PID> or --name <NAME>"),
        (Some(pid), None) => OwnedProcess::from_pid(pid)
            .with_context(|| format!("failed to open process with pid {pid}")),
        (None, Some(name)) => resolve_by_name(name, target.first),
    }
}

fn resolve_by_name(name: &str, first: bool) -> Result<OwnedProcess> {
    let mut matches = OwnedProcess::find_all_by_name(name);

    match matches.len() {
        0 => bail!("no running process matches '{name}'"),
        1 => Ok(matches.remove(0)),
        _ if first => Ok(matches.remove(0)),
        _ => {
            let mut message = format!("{} processes match '{name}':\n", matches.len());
            for process in &matches {
                message.push_str(&format!("  {}\n", describe(process)));
            }
            message.push_str("pass --first to use the first match, or use --pid to disambiguate");
            bail!(message)
        }
    }
}

/// Builds a short human readable description of a process.
pub fn describe(process: &OwnedProcess) -> String {
    let pid = process.pid().map(|pid| pid.get()).unwrap_or(0);
    let name = process
        .base_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let arch = match process.is_x64() {
        Ok(true) => "x64",
        _ => match process.is_x86() {
            Ok(true) => "x86",
            _ => "?",
        },
    };

    format!("{name} (pid {pid}, {arch})")
}

/// Finds a loaded module by path, falling back to matching by file name.
///
/// A bare file name (no directory component) is matched by name only, so
/// callers can pass `foo.dll` as well as `C:\path\to\foo.dll`.
pub fn find_loaded_module<'a>(
    process: BorrowedProcess<'a>,
    dll: &Path,
) -> Result<Option<BorrowedProcessModule<'a>>> {
    let has_dir = dll.is_absolute() || dll.components().count() > 1;

    if has_dir {
        if let Some(module) = process.find_module_by_path(dll)? {
            return Ok(Some(module));
        }
        if let Some(name) = dll.file_name() {
            return Ok(process.find_module_by_name(name)?);
        }
        Ok(None)
    } else {
        Ok(process.find_module_by_name(dll)?)
    }
}
