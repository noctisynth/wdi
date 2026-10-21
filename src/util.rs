//! Small shared helpers.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Verifies that `path` points to an existing regular file.
pub fn ensure_file(path: &Path, what: &str) -> Result<()> {
    if !path.exists() {
        bail!("{what} not found: {}", path.display());
    }
    if !path.is_file() {
        bail!("{what} is not a file: {}", path.display());
    }
    Ok(())
}

/// Resolves an executable path, searching `PATH` for bare file names such as
/// `notepad.exe`.
pub fn resolve_executable(exe: &Path) -> Result<PathBuf> {
    if exe.is_file() {
        return Ok(exe.to_path_buf());
    }

    // Anything with a directory component (or an absolute path) must exist as-is.
    if exe.is_absolute() || exe.components().count() > 1 {
        bail!("executable not found: {}", exe.display());
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Ok(candidate);
            }
            if exe.extension().is_none() {
                let mut with_ext = exe.as_os_str().to_os_string();
                with_ext.push(".exe");
                let candidate = dir.join(with_ext);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    bail!("executable not found on PATH: {}", exe.display())
}

/// Pads `s` on the left with spaces to `width` columns.
pub fn pad_left(s: &str, width: usize) -> String {
    format!("{s:>width$}")
}

/// Pads `s` on the right with spaces to `width` columns.
pub fn pad_right(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}
