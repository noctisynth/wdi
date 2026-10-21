//! `wdi list`

use anyhow::Result;
use dll_syringe::process::{OwnedProcess, Process};

use crate::cli::ListArgs;
use crate::util::{pad_left, pad_right};

struct Row {
    pid: u32,
    arch: &'static str,
    name: String,
    path: String,
}

pub fn run(args: ListArgs) -> Result<()> {
    let filter = args.filter.as_deref().map(str::to_lowercase);

    let mut rows = Vec::new();
    for process in OwnedProcess::all() {
        let Ok(pid) = process.pid() else { continue };

        let name = process
            .base_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        if let Some(filter) = &filter
            && !name.to_lowercase().contains(filter)
        {
            continue;
        }

        let arch = match process.is_x64() {
            Ok(true) => "x64",
            _ => match process.is_x86() {
                Ok(true) => "x86",
                _ => "?",
            },
        };

        let path = if args.paths {
            process
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        rows.push(Row {
            pid: pid.get(),
            arch,
            name,
            path,
        });
    }

    if rows.is_empty() {
        println!("No matching processes.");
        return Ok(());
    }

    rows.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.pid.cmp(&b.pid))
    });

    let pid_width = rows
        .iter()
        .map(|row| row.pid.to_string().len())
        .max()
        .unwrap_or(3)
        .max(3);
    let name_width = rows
        .iter()
        .map(|row| row.name.len())
        .max()
        .unwrap_or(4)
        .max(4);

    if args.paths {
        println!(
            "{}  {}  {}  PATH",
            pad_left("PID", pid_width),
            pad_right("ARCH", 4),
            pad_right("NAME", name_width)
        );
        for row in &rows {
            println!(
                "{}  {}  {}  {}",
                pad_left(&row.pid.to_string(), pid_width),
                pad_right(row.arch, 4),
                pad_right(&row.name, name_width),
                row.path
            );
        }
    } else {
        println!(
            "{}  {}  NAME",
            pad_left("PID", pid_width),
            pad_right("ARCH", 4)
        );
        for row in &rows {
            println!(
                "{}  {}  {}",
                pad_left(&row.pid.to_string(), pid_width),
                pad_right(row.arch, 4),
                row.name
            );
        }
    }

    Ok(())
}
