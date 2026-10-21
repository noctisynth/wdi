//! Reflective DLL loading.
//!
//! Unlike classic injection, the target never calls `LoadLibrary`. The DLL is
//! materialised directly in the target's address space: headers and sections
//! are copied, relocations and imports are applied, and a small generated
//! bootstrap calls the DLL entry point.
//!
//! Reflective modules are invisible to the Windows module list. They cannot be
//! found by `wdi list` and cannot be unloaded with `wdi eject`.

mod pe;
mod shim;

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use dll_syringe::process::{BorrowedProcess, Process};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx,
};

use self::pe::PeImage;
use self::shim::ShimPlan;

/// Summary of a successful reflective load.
pub struct LoadReport {
    pub image_base: u64,
    pub image_size: usize,
    pub entry_point: Option<u64>,
    pub imports: usize,
    pub delay_imports: usize,
    pub skipped_delay_imports: usize,
    pub tls_callbacks: usize,
    pub exception_entries: u32,
    pub warnings: Vec<String>,
}

/// Reflectively loads `dll` into `process`.
pub fn inject(process: BorrowedProcess<'_>, dll: &Path) -> Result<LoadReport> {
    let bytes = fs::read(dll).with_context(|| format!("failed to read '{}'", dll.display()))?;
    let pe = PeImage::parse(&bytes)
        .with_context(|| format!("failed to parse '{}' as a PE image", dll.display()))?;

    if !pe.is_dll() {
        bail!(
            "'{}' is not a DLL (the IMAGE_FILE_DLL characteristic is not set)",
            dll.display()
        );
    }

    let host_is_64 = cfg!(target_arch = "x86_64");
    if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        bail!("reflective loading is only supported on x86 and x64 wdi builds");
    }
    if pe.is_64 != host_is_64 {
        bail!(
            "reflective loading requires the DLL bitness to match wdi's bitness ({}), but '{}' is {}-bit",
            if host_is_64 { "x64" } else { "x86" },
            dll.display(),
            if pe.is_64 { "64" } else { "32" }
        );
    }

    let target_is_64 = process.is_x64().unwrap_or(false);
    let target_is_32 = process.is_x86().unwrap_or(false);
    if !(target_is_64 || target_is_32) {
        bail!("could not determine the target's architecture");
    }
    if target_is_64 != host_is_64 {
        bail!(
            "reflective loading does not support cross-architecture injection; \
             wdi and the target must both be {}-bit (use classic injection without --reflective instead)",
            if host_is_64 { "64" } else { "32" }
        );
    }

    let (mut warnings, deferred_delay_imports) = ensure_import_bases(process, &pe)?;

    // Prefer the image's preferred base. If it is unavailable the image is
    // rebased, which requires a relocation table.
    let preferred = pe.image_base;
    let image_allocation = alloc_remote(process, Some(preferred), pe.size_of_image)
        .context("failed to allocate memory for the mapped image")?;
    let remote_base = image_allocation as u64;

    if !pe.relocations_present() && remote_base != preferred {
        free_remote(process, image_allocation);
        bail!(
            "the DLL cannot be rebased (it has no relocation table), but its preferred base \
             0x{preferred:x} is unavailable in the target"
        );
    }

    let mapped = match pe.map(remote_base, &deferred_delay_imports) {
        Ok(mapped) => mapped,
        Err(err) => {
            free_remote(process, image_allocation);
            return Err(err.context("failed to build the mapped image"));
        }
    };

    if let Err(err) = write_remote(process, image_allocation, &mapped.bytes) {
        free_remote(process, image_allocation);
        return Err(err.context("failed to write the mapped image"));
    }

    let rtl_add_function_table = if mapped.exception_table.is_some() {
        resolve_function(b"ntdll.dll\0", b"RtlAddFunctionTable\0")
    } else {
        None
    };
    if mapped.exception_table.is_some() && rtl_add_function_table.is_none() {
        warnings.push(
            "could not resolve RtlAddFunctionTable; x64 exception handling may not work"
                .to_string(),
        );
    }

    let set_process_valid_call_targets = if mapped.uses_cfg {
        resolve_function(b"kernelbase.dll\0", b"SetProcessValidCallTargets\0")
            .or_else(|| resolve_function(b"kernel32.dll\0", b"SetProcessValidCallTargets\0"))
    } else {
        None
    };
    if mapped.uses_cfg && set_process_valid_call_targets.is_none() {
        warnings.push(
            "the DLL is Control Flow Guard instrumented, but SetProcessValidCallTargets could not \
             be resolved; CFG checks may fail"
                .to_string(),
        );
    }

    let cfg_bytes = if set_process_valid_call_targets.is_some() {
        mapped
            .cfg_targets
            .iter()
            .flat_map(|target| target.to_bytes())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let cfg_allocation = if cfg_bytes.is_empty() {
        None
    } else {
        match alloc_remote(process, None, cfg_bytes.len()).and_then(|allocation| {
            write_remote(process, allocation, &cfg_bytes).map(|()| allocation)
        }) {
            Ok(allocation) => Some(allocation),
            Err(err) => {
                free_remote(process, image_allocation);
                return Err(err.context("failed to prepare CFG call targets"));
            }
        }
    };

    let shim_bytes = shim::build(&ShimPlan {
        image_base: remote_base,
        image_size: pe.size_of_image as u64,
        entry_point: mapped.entry_point,
        tls_callbacks: &mapped.tls_callbacks,
        exception_table: mapped.exception_table,
        rtl_add_function_table,
        cfg_targets: cfg_allocation
            .map(|allocation| (allocation as u64, mapped.cfg_targets.len() as u32)),
        set_process_valid_call_targets,
    });

    let shim_allocation = match alloc_remote(process, None, shim_bytes.len()) {
        Ok(allocation) => allocation,
        Err(err) => {
            free_remote_optional(process, cfg_allocation);
            free_remote(process, image_allocation);
            return Err(err.context("failed to allocate memory for the loader shim"));
        }
    };

    if let Err(err) = write_remote(process, shim_allocation, &shim_bytes).and_then(|()| {
        protect_remote(
            process,
            shim_allocation,
            shim_bytes.len(),
            PAGE_EXECUTE_READ,
        )
    }) {
        free_remote(process, shim_allocation);
        free_remote_optional(process, cfg_allocation);
        free_remote(process, image_allocation);
        return Err(err.context("failed to prepare the loader shim"));
    }

    if let Err(err) = protect_image(process, &pe, remote_base) {
        free_remote(process, shim_allocation);
        free_remote_optional(process, cfg_allocation);
        free_remote(process, image_allocation);
        return Err(err.context("failed to apply section protections"));
    }

    let start: extern "system" fn(*mut u8) -> u32 = unsafe { std::mem::transmute(shim_allocation) };
    let exit_code = process.run_remote_thread(start, std::ptr::null_mut());

    free_remote(process, shim_allocation);
    free_remote_optional(process, cfg_allocation);

    let exit_code = match exit_code {
        Ok(code) => code,
        Err(err) => {
            free_remote(process, image_allocation);
            return Err(anyhow!(err).context("failed to run the reflective loader thread"));
        }
    };

    if exit_code == 0 {
        free_remote(process, image_allocation);
        bail!("the DLL entry point returned FALSE (reflective load failed)");
    }

    if mapped.skipped_delay_imports > 0 {
        warnings.push(format!(
            "{} delay-loaded library(ies) could not be prepared eagerly and will be resolved \
             on first use by the DLL's delay-load thunks",
            mapped.skipped_delay_imports
        ));
    }
    if mapped.has_tls {
        warnings.push(
            "the DLL has a TLS directory; static thread-local data may not work when the DLL \
             is reflectively loaded"
                .to_string(),
        );
    }
    Ok(LoadReport {
        image_base: remote_base,
        image_size: pe.size_of_image,
        entry_point: mapped.entry_point,
        imports: mapped.imports,
        delay_imports: mapped.delay_imports,
        skipped_delay_imports: mapped.skipped_delay_imports,
        tls_callbacks: mapped.tls_callbacks.len(),
        exception_entries: mapped.exception_table.map(|(_, count)| count).unwrap_or(0),
        warnings,
    })
}

/// Makes sure every imported library is loaded in the target at the same base
/// as in the injector.
///
/// Import addresses are resolved in the injector process, which is correct for
/// system DLLs (their mapping is shared across processes) but not for a module
/// that gets a different base in the target. Regular imports with a detected
/// mismatch fail the load; delay imports with a mismatch stay lazy.
fn ensure_import_bases(
    process: BorrowedProcess<'_>,
    pe: &PeImage<'_>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut deferred = Vec::new();

    // Regular imports are mandatory: every one of them must be usable at the
    // same address in the target.
    for module_name in pe.imported_modules()? {
        prepare_module(process, &module_name, true, &mut warnings)?;
    }

    // Delay imports can stay lazy. Only prepare the ones whose base we can
    // verify; the rest keep their original delay-load thunks.
    for module_name in pe.delay_imported_modules()? {
        if !prepare_module(process, &module_name, false, &mut warnings)? {
            deferred.push(module_name);
        }
    }

    Ok((warnings, deferred))
}

fn prepare_module(
    process: BorrowedProcess<'_>,
    module_name: &str,
    required: bool,
    warnings: &mut Vec<String>,
) -> Result<bool> {
    let mut name_with_nul = module_name.as_bytes().to_vec();
    name_with_nul.push(0);

    let host_base = unsafe { LoadLibraryA(name_with_nul.as_ptr()) };
    if host_base.is_null() {
        if required {
            bail!(
                "failed to load imported library '{}' in the injector process",
                module_name
            );
        }
        return Ok(false);
    }

    let mut target_base = find_target_module(process, module_name)?;
    let is_api_set = is_api_set_name(module_name);

    if target_base.is_none() && !is_api_set {
        let loaded = load_module_in_target(process, &name_with_nul).with_context(|| {
            format!("failed to load imported library '{module_name}' in the target")
        });
        if let Err(err) = loaded {
            if required {
                return Err(err);
            }
            return Ok(false);
        }
        target_base = find_target_module(process, module_name)?;
        if target_base.is_none() {
            if required {
                bail!(
                    "LoadLibrary returned in the target, but imported library '{module_name}' \
                     is still not visible in its module list"
                );
            }
            return Ok(false);
        }
    }

    match target_base {
        Some(target_base) if target_base == host_base as usize => Ok(true),
        Some(target_base) => {
            if required {
                bail!(
                    "imported library '{module_name}' is mapped at 0x{:x} in wdi but \
                     0x{target_base:x} in the target; reflective loading requires shared import \
                     bases (use classic injection for this DLL)",
                    host_base as usize
                );
            }
            Ok(false)
        }
        None => {
            if is_api_set {
                // API set names are not real modules; the resolved host module
                // is normally shared at the same address in the target.
                Ok(true)
            } else if required {
                warnings.push(format!(
                    "could not verify the base address of imported library '{module_name}'"
                ));
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

fn find_target_module(process: BorrowedProcess<'_>, name: &str) -> Result<Option<usize>> {
    match process.find_module_by_name(name) {
        Ok(module) => Ok(module.map(|module| module.handle() as usize)),
        Err(err) => Err(anyhow!(err).context(format!("failed to look up module '{name}'"))),
    }
}

fn load_module_in_target(process: BorrowedProcess<'_>, name_with_nul: &[u8]) -> Result<()> {
    let remote_name = alloc_remote(process, None, name_with_nul.len())?;
    if let Err(err) = write_remote(process, remote_name, name_with_nul) {
        free_remote(process, remote_name);
        return Err(err);
    }

    let load_library = resolve_function(b"kernel32.dll\0", b"LoadLibraryA\0")
        .ok_or_else(|| anyhow!("could not resolve LoadLibraryA"))?;
    let start: extern "system" fn(*mut u8) -> u32 = unsafe { std::mem::transmute(load_library) };

    let result = process.run_remote_thread(start, remote_name as *mut u8);
    free_remote(process, remote_name);
    result
        .map(|_| ())
        .context("remote LoadLibraryA call failed")
}

fn is_api_set_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("api-ms-win-") || name.starts_with("ext-ms-win-")
}

fn protect_image(process: BorrowedProcess<'_>, pe: &PeImage<'_>, image_base: u64) -> Result<()> {
    let headers_len = pe.size_of_headers.min(pe.size_of_image);
    if headers_len > 0 {
        protect_remote(
            process,
            image_base as *const c_void,
            headers_len,
            PAGE_READONLY,
        )?;
    }

    for section in &pe.sections {
        let size = section.virtual_size.max(section.raw_size) as usize;
        if size == 0 {
            continue;
        }
        let address = image_base
            .checked_add(section.virtual_address as u64)
            .ok_or_else(|| anyhow!("section '{}' address overflow", section.name))?;
        protect_remote(
            process,
            address as *const c_void,
            size,
            PeImage::section_protection(section),
        )
        .with_context(|| format!("failed to protect section '{}'", section.name))?;
    }

    Ok(())
}

fn resolve_function(module_name: &[u8], function_name: &[u8]) -> Option<u64> {
    let module = unsafe { GetModuleHandleA(module_name.as_ptr()) };
    if module.is_null() {
        return None;
    }
    let function = unsafe { GetProcAddress(module, function_name.as_ptr()) }?;
    Some(function as usize as u64)
}

fn alloc_remote(
    process: BorrowedProcess<'_>,
    preferred: Option<u64>,
    size: usize,
) -> Result<*mut c_void> {
    let handle = process_handle(process);
    let mut address = std::ptr::null_mut();

    if let Some(preferred) = preferred {
        address = unsafe {
            VirtualAllocEx(
                handle,
                preferred as *const c_void,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
    }

    if address.is_null() {
        address = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
    }

    if address.is_null() {
        bail!(
            "VirtualAllocEx failed to allocate {size} bytes: {}",
            io::Error::last_os_error()
        );
    }

    Ok(address)
}

fn free_remote(process: BorrowedProcess<'_>, address: *mut c_void) {
    if !address.is_null() {
        unsafe { VirtualFreeEx(process_handle(process), address, 0, MEM_RELEASE) };
    }
}

fn free_remote_optional(process: BorrowedProcess<'_>, address: Option<*mut c_void>) {
    if let Some(address) = address {
        free_remote(process, address);
    }
}

fn write_remote(process: BorrowedProcess<'_>, address: *mut c_void, bytes: &[u8]) -> Result<()> {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process_handle(process),
            address,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            &mut written,
        )
    };
    if ok == 0 || written != bytes.len() {
        bail!(
            "WriteProcessMemory failed for {} bytes: {}",
            bytes.len(),
            io::Error::last_os_error()
        );
    }
    Ok(())
}

fn protect_remote(
    process: BorrowedProcess<'_>,
    address: *const c_void,
    size: usize,
    protection: u32,
) -> Result<()> {
    let mut old_protection = 0u32;
    let ok = unsafe {
        VirtualProtectEx(
            process_handle(process),
            address,
            size,
            protection,
            &mut old_protection,
        )
    };
    if ok == 0 {
        bail!(
            "VirtualProtectEx failed for {} bytes at {:p}: {}",
            size,
            address,
            io::Error::last_os_error()
        );
    }
    Ok(())
}

fn process_handle(process: BorrowedProcess<'_>) -> HANDLE {
    process.as_raw_handle() as HANDLE
}
