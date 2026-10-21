//! `wdi inject`

use anyhow::{Context, Result};
use dll_syringe::Syringe;

use crate::cli::InjectArgs;
use crate::target;
use crate::util::ensure_file;

pub fn run(args: InjectArgs) -> Result<()> {
    ensure_file(&args.dll, "DLL")?;

    let process = target::resolve(&args.target)?;
    println!("Target   : {}", target::describe(&process));
    println!("Payload  : {}", args.dll.display());

    let syringe = Syringe::for_process(process);

    if args.if_missing
        && let Some(module) = target::find_loaded_module(syringe.process(), &args.dll)?
    {
        let loaded = module
            .path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| args.dll.display().to_string());
        println!("Already  : {loaded} (nothing to do)");
        return Ok(());
    }

    if args.reflective {
        println!("Method   : reflective (manual mapping)");

        let report = crate::reflective::inject(syringe.process(), &args.dll)
            .with_context(|| format!("failed to reflectively load '{}'", args.dll.display()))?;

        println!(
            "Mapped   : base 0x{:x}, entry {}, image {} bytes",
            report.image_base,
            report
                .entry_point
                .map(|entry| format!("0x{entry:x}"))
                .unwrap_or_else(|| "<none>".to_string()),
            report.image_size
        );
        println!(
            "Imports  : {} (delay-loaded: {}, deferred: {}), TLS callbacks: {}, x64 unwind entries: {}",
            report.imports,
            report.delay_imports,
            report.skipped_delay_imports,
            report.tls_callbacks,
            report.exception_entries
        );
        for warning in &report.warnings {
            eprintln!("warning: {warning}");
        }
        println!("Injected : {} (reflective)", args.dll.display());
        return Ok(());
    }

    let module = syringe
        .inject(&args.dll)
        .with_context(|| format!("failed to inject '{}'", args.dll.display()))?;

    let loaded = module
        .path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| args.dll.display().to_string());

    println!("Injected : {loaded}");
    Ok(())
}
