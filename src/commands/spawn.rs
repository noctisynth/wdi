//! `wdi spawn` — launch a process and inject a DLL into it.
//!
//! By default the process is created suspended, so the DLL is loaded before any
//! of the target's own code runs. Use `--unsuspended` to create it running and
//! inject afterwards.

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use anyhow::{Result, bail};
use dll_syringe::Syringe;
use dll_syringe::process::OwnedProcess;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess, INFINITE, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW, WaitForSingleObject,
};

use crate::cli::SpawnArgs;
use crate::util::{ensure_file, resolve_executable};

pub fn run(args: SpawnArgs) -> Result<()> {
    let exe = resolve_executable(&args.exe)?;
    if let Some(dll) = &args.dll {
        ensure_file(dll, "DLL")?;
    }

    let suspended = !args.unsuspended;

    let mut exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut command_line = build_command_line(&exe, &args.args);

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = unsafe {
        CreateProcessW(
            exe_wide.as_mut_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            if suspended { CREATE_SUSPENDED } else { 0 },
            std::ptr::null(),
            std::ptr::null(),
            &startup_info,
            &mut process_info,
        )
    };

    if created == 0 {
        bail!(
            "failed to launch '{}': {}",
            exe.display(),
            std::io::Error::last_os_error()
        );
    }

    let pid = process_info.dwProcessId;
    let thread_handle = process_info.hThread;
    let process_handle = process_info.hProcess;

    // `OwnedProcess` takes ownership of the process handle and closes it on drop.
    let process = unsafe { OwnedProcess::from_raw_handle(process_handle) };

    let syringe = if suspended {
        match Syringe::for_suspended_process(process) {
            Ok(syringe) => syringe,
            Err(err) => {
                resume(thread_handle, suspended);
                unsafe { CloseHandle(thread_handle) };
                return Err(anyhow::Error::new(err).context("failed to attach to the new process"));
            }
        }
    } else {
        Syringe::for_process(process)
    };

    if let Some(dll) = &args.dll {
        if args.reflective {
            match crate::reflective::inject(syringe.process(), dll) {
                Ok(report) => {
                    println!(
                        "Reflectively mapped '{}' into pid {pid} (base 0x{:x}, image {} bytes)",
                        dll.display(),
                        report.image_base,
                        report.image_size
                    );
                    for warning in &report.warnings {
                        eprintln!("warning: {warning}");
                    }
                }
                Err(err) => {
                    resume(thread_handle, suspended);
                    unsafe { CloseHandle(thread_handle) };
                    return Err(
                        err.context(format!("failed to reflectively load '{}'", dll.display()))
                    );
                }
            }
        } else {
            if let Err(err) = syringe.inject(dll) {
                resume(thread_handle, suspended);
                unsafe { CloseHandle(thread_handle) };
                return Err(anyhow::Error::new(err)
                    .context(format!("failed to inject '{}'", dll.display())));
            }
            println!("Injected '{}' into pid {pid}", dll.display());
        }
    } else {
        println!("Started pid {pid} (no DLL requested)");
    }

    resume(thread_handle, suspended);
    unsafe { CloseHandle(thread_handle) };

    if args.wait {
        unsafe { WaitForSingleObject(process_handle, INFINITE) };
        let mut code: u32 = 0;
        unsafe { GetExitCodeProcess(process_handle, &mut code) };
        println!("Process {pid} exited with code {}", code as i32);
    }

    Ok(())
}

/// Resumes the main thread if the process was created suspended.
fn resume(thread_handle: *mut core::ffi::c_void, suspended: bool) {
    if suspended {
        unsafe { ResumeThread(thread_handle) };
    }
}

/// Quotes a single command line argument following the conventions expected by
/// the Windows C runtime.
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
                quoted.push('\\');
            }
            '"' => {
                // Escape the backslashes that precede a literal quote.
                for _ in 0..backslashes {
                    quoted.push('\\');
                }
                backslashes = 0;
                quoted.push('\\');
                quoted.push('"');
            }
            _ => {
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    // Escape trailing backslashes so they do not escape the closing quote.
    for _ in 0..backslashes {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

fn build_command_line(exe: &Path, args: &[String]) -> Vec<u16> {
    let mut line = quote_arg(&exe.to_string_lossy());
    for arg in args {
        line.push(' ');
        line.push_str(&quote_arg(arg));
    }
    line.encode_utf16().chain(std::iter::once(0)).collect()
}
