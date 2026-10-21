//! `wdi eject`

use anyhow::{Context, Result};
use dll_syringe::Syringe;

use crate::cli::EjectArgs;
use crate::target;

pub fn run(args: EjectArgs) -> Result<()> {
    let process = target::resolve(&args.target)?;
    println!("Target : {}", target::describe(&process));

    let syringe = Syringe::for_process(process);

    let module = target::find_loaded_module(syringe.process(), &args.dll)
        .with_context(|| format!("failed to look up '{}'", args.dll.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "'{}' is not loaded in the target process",
                args.dll.display()
            )
        })?;

    let loaded = module
        .path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| args.dll.display().to_string());

    syringe
        .eject(module)
        .with_context(|| format!("failed to eject '{loaded}'"))?;

    println!("Ejected : {loaded}");
    Ok(())
}
