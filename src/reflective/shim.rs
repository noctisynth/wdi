//! Generates the tiny in-target bootstrap used by reflective loading.
//!
//! `CreateRemoteThread` only passes a single argument, while `DllMain` needs
//! three. The shim is therefore generated with all addresses baked in: it
//! registers CFG call targets, optionally registers the x64 exception table,
//! runs TLS callbacks, and then calls the DLL entry point with
//! `DLL_PROCESS_ATTACH`.

/// Everything the bootstrap needs. All addresses are absolute, in the target.
pub struct ShimPlan<'a> {
    pub image_base: u64,
    pub image_size: u64,
    pub entry_point: Option<u64>,
    pub tls_callbacks: &'a [u64],
    pub exception_table: Option<(u64, u32)>,
    pub rtl_add_function_table: Option<u64>,
    pub cfg_targets: Option<(u64, u32)>,
    pub set_process_valid_call_targets: Option<u64>,
}

#[cfg(target_arch = "x86_64")]
pub fn build(plan: &ShimPlan<'_>) -> Vec<u8> {
    let mut code = Vec::new();

    // SetProcessValidCallTargets(GetCurrentProcess(), base, size, count, targets)
    if let (Some((targets, count)), Some(function)) =
        (plan.cfg_targets, plan.set_process_valid_call_targets)
    {
        mov_rcx(&mut code, u64::MAX);
        mov_rdx(&mut code, plan.image_base);
        mov_r8(&mut code, plan.image_size);
        mov_r9d(&mut code, count);
        code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28
        code.extend_from_slice(&[0x48, 0xb8]); // mov rax, targets
        code.extend_from_slice(&targets.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
        code.extend_from_slice(&[0x48, 0xb8]); // mov rax, function
        code.extend_from_slice(&function.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xd0]); // call rax
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 0x28
    }

    // RtlAddFunctionTable(table, count, image_base)
    if let (Some((table, count)), Some(function)) =
        (plan.exception_table, plan.rtl_add_function_table)
    {
        mov_rcx(&mut code, table);
        mov_edx(&mut code, count);
        mov_r8(&mut code, plan.image_base);
        call_absolute(&mut code, function);
    }

    // TLS callbacks get (image_base, DLL_PROCESS_ATTACH, NULL).
    for &callback in plan.tls_callbacks {
        mov_rcx(&mut code, plan.image_base);
        mov_edx(&mut code, 1);
        xor_r8d(&mut code);
        call_absolute(&mut code, callback);
    }

    // DllMain(image_base, DLL_PROCESS_ATTACH, NULL).
    if let Some(entry_point) = plan.entry_point {
        mov_rcx(&mut code, plan.image_base);
        mov_edx(&mut code, 1);
        xor_r8d(&mut code);
        call_absolute(&mut code, entry_point);
    } else {
        // No entry point: report success.
        code.extend_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, 1
    }

    code.push(0xc3); // ret
    code
}

#[cfg(target_arch = "x86_64")]
fn mov_rcx(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xb9]);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn mov_rdx(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xba]);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn mov_edx(code: &mut Vec<u8>, value: u32) {
    code.push(0xba);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn mov_r9d(code: &mut Vec<u8>, value: u32) {
    code.extend_from_slice(&[0x41, 0xb9]);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn mov_r8(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x49, 0xb8]);
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
fn xor_r8d(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x45, 0x31, 0xc0]);
}

#[cfg(target_arch = "x86_64")]
fn call_absolute(code: &mut Vec<u8>, function: u64) {
    code.extend_from_slice(&[0x48, 0xb8]); // mov rax, function
    code.extend_from_slice(&function.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]); // sub rsp, 0x28 (align + shadow)
    code.extend_from_slice(&[0xff, 0xd0]); // call rax
    code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]); // add rsp, 0x28
}

#[cfg(target_arch = "x86")]
pub fn build(plan: &ShimPlan<'_>) -> Vec<u8> {
    let mut code = Vec::new();

    // SetProcessValidCallTargets(GetCurrentProcess(), base, size, count, targets)
    if let (Some((targets, count)), Some(function)) =
        (plan.cfg_targets, plan.set_process_valid_call_targets)
    {
        push(&mut code, targets as u32);
        push(&mut code, count);
        push(&mut code, plan.image_size as u32);
        push(&mut code, plan.image_base as u32);
        push(&mut code, u32::MAX); // pseudo-handle for the current process
        call_absolute(&mut code, function as u32);
    }

    // TLS callbacks get (image_base, DLL_PROCESS_ATTACH, NULL).
    for &callback in plan.tls_callbacks {
        push(&mut code, plan.image_base as u32);
        push(&mut code, 1);
        push(&mut code, 0);
        call_absolute(&mut code, callback as u32);
    }

    // DllMain(image_base, DLL_PROCESS_ATTACH, NULL), stdcall.
    if let Some(entry_point) = plan.entry_point {
        push(&mut code, plan.image_base as u32);
        push(&mut code, 1);
        push(&mut code, 0);
        call_absolute(&mut code, entry_point as u32);
        code.extend_from_slice(&[0xc2, 0x04, 0x00]); // ret 4
    } else {
        code.extend_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, 1
        code.extend_from_slice(&[0xc2, 0x04, 0x00]); // ret 4
    }

    code
}

#[cfg(target_arch = "x86")]
fn push(code: &mut Vec<u8>, value: u32) {
    code.push(0x68); // push imm32
    code.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86")]
fn call_absolute(code: &mut Vec<u8>, function: u32) {
    code.push(0xb8); // mov eax, function
    code.extend_from_slice(&function.to_le_bytes());
    code.extend_from_slice(&[0xff, 0xd0]); // call eax
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub fn build(_plan: &ShimPlan<'_>) -> Vec<u8> {
    Vec::new()
}
