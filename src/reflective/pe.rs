//! A small, bounds-checked PE parser that builds a mapped image in memory.
//!
//! This is the host-side half of reflective loading. It intentionally does not
//! depend on the Windows loader: the image is laid out the same way the loader
//! would lay it out, then imports/relocations are applied manually.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

const IMAGE_FILE_DLL: u16 = 0x2000;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

const IMAGE_ORDINAL_FLAG32: u64 = 0x8000_0000;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const CFG_CALL_TARGET_VALID: usize = 0x0000_0001;

/// Mirrors `CFG_CALL_TARGET_INFO` (two `ULONG_PTR`s).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CfgTarget {
    pub offset: usize,
    pub flags: usize,
}

impl CfgTarget {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<Self>());
        bytes.extend_from_slice(&self.offset.to_le_bytes());
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

/// A parsed PE image.
#[derive(Debug)]
pub struct PeImage<'a> {
    bytes: &'a [u8],
    pub is_64: bool,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub characteristics: u16,
    pub sections: Vec<Section>,
    directories: [DataDirectory; 16],
}

/// The result of mapping a PE image and resolving everything it needs.
pub struct MappedImage {
    /// The fully materialised image, ready to be written to the target.
    pub bytes: Vec<u8>,
    /// Absolute address of the entry point in the target process.
    pub entry_point: Option<u64>,
    /// Absolute addresses of TLS callbacks that should run before `DllMain`.
    pub tls_callbacks: Vec<u64>,
    /// x64 `.pdata` table: `(absolute address, entry count)`.
    pub exception_table: Option<(u64, u32)>,
    pub imports: usize,
    pub delay_imports: usize,
    pub skipped_delay_imports: usize,
    /// Whether the image declares a TLS directory.
    pub has_tls: bool,
    /// Whether the image was built with Control Flow Guard.
    pub uses_cfg: bool,
    /// Valid indirect-call targets that must be registered with the OS.
    pub cfg_targets: Vec<CfgTarget>,
}

impl<'a> PeImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 0x40 {
            bail!("file is too small to be a PE image");
        }
        if read_u16(bytes, 0)? != IMAGE_DOS_SIGNATURE {
            bail!("missing MZ signature");
        }

        let nt_offset = read_u32(bytes, 0x3c)? as usize;
        let nt_end = nt_offset
            .checked_add(4 + 20)
            .ok_or_else(|| anyhow!("invalid e_lfanew"))?;
        if nt_end > bytes.len() {
            bail!(
                "e_lfanew (0x{nt_offset:x}) points past the end of the file ({} bytes)",
                bytes.len()
            );
        }
        if read_u32(bytes, nt_offset)? != IMAGE_NT_SIGNATURE {
            bail!("missing PE signature");
        }

        let file_header = nt_offset + 4;
        let machine = read_u16(bytes, file_header)?;
        let section_count = read_u16(bytes, file_header + 2)? as usize;
        let size_of_optional_header = read_u16(bytes, file_header + 16)? as usize;
        let characteristics = read_u16(bytes, file_header + 18)?;
        let optional = file_header + 20;
        let optional_end = optional
            .checked_add(size_of_optional_header)
            .ok_or_else(|| anyhow!("invalid SizeOfOptionalHeader"))?;
        if optional_end > bytes.len() {
            bail!("optional header extends past the end of the file");
        }

        let magic = read_u16(bytes, optional)?;
        let is_64 = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
            other => bail!("unknown optional header magic 0x{other:04x}"),
        };

        let (minimum_optional_size, image_base, directory_offset) = if is_64 {
            (112usize, read_u64(bytes, optional + 24)?, optional + 112)
        } else {
            (
                96usize,
                read_u32(bytes, optional + 28)? as u64,
                optional + 96,
            )
        };
        if size_of_optional_header < minimum_optional_size {
            bail!(
                "optional header is too small for a {} image ({} bytes)",
                if is_64 { "PE32+" } else { "PE32" },
                size_of_optional_header
            );
        }

        let entry_point_rva = read_u32(bytes, optional + 16)?;
        let size_of_image = read_u32(bytes, optional + 56)? as usize;
        let size_of_headers = read_u32(bytes, optional + 60)? as usize;
        if size_of_image == 0 {
            bail!("SizeOfImage is zero");
        }
        if size_of_image > 1 << 30 {
            bail!("SizeOfImage is unreasonably large (0x{size_of_image:x} bytes)");
        }
        if size_of_headers == 0 {
            bail!("SizeOfHeaders is zero");
        }
        if size_of_headers > size_of_image {
            bail!(
                "SizeOfHeaders (0x{size_of_headers:x}) exceeds SizeOfImage (0x{size_of_image:x})"
            );
        }
        if size_of_headers > bytes.len() {
            bail!("SizeOfHeaders extends past the end of the file");
        }
        if entry_point_rva as usize >= size_of_image {
            bail!(
                "entry point RVA 0x{entry_point_rva:x} is outside the image (0x{size_of_image:x} bytes)"
            );
        }

        match (machine, is_64) {
            (IMAGE_FILE_MACHINE_I386, false) | (IMAGE_FILE_MACHINE_AMD64, true) => {}
            (IMAGE_FILE_MACHINE_I386, true) => bail!("PE32+ image is marked as i386"),
            (IMAGE_FILE_MACHINE_AMD64, false) => bail!("PE32 image is marked as amd64"),
            (other, _) => {
                bail!("unsupported PE machine 0x{other:04x} (only x86 and x64 are supported)")
            }
        }

        let mut directories = [DataDirectory::default(); 16];
        let number_of_directories = if is_64 {
            read_u32(bytes, optional + 108)? as usize
        } else {
            read_u32(bytes, optional + 92)? as usize
        };
        for (index, directory) in directories.iter_mut().enumerate() {
            if index >= number_of_directories {
                break;
            }
            let offset = directory_offset + index * 8;
            if offset + 8 > optional_end {
                break;
            }
            directory.virtual_address = read_u32(bytes, offset)?;
            directory.size = read_u32(bytes, offset + 4)?;
        }

        if section_count > 96 {
            bail!("PE contains {section_count} sections (Windows supports at most 96)");
        }
        let section_table = optional_end;
        let section_table_end = section_table
            .checked_add(section_count * 40)
            .ok_or_else(|| anyhow!("invalid section table size"))?;
        if section_table_end > bytes.len() {
            bail!("section table extends past the end of the file");
        }
        if section_table_end > size_of_headers {
            bail!("SizeOfHeaders does not cover the section table");
        }

        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = section_table + index * 40;
            let name_bytes = &bytes[offset..offset + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let virtual_size = read_u32(bytes, offset + 8)?;
            let virtual_address = read_u32(bytes, offset + 12)?;
            let raw_size = read_u32(bytes, offset + 16)?;
            let raw_offset = read_u32(bytes, offset + 20)?;
            let section_characteristics = read_u32(bytes, offset + 36)?;

            if raw_size > 0 {
                if virtual_address < size_of_headers as u32 {
                    bail!("section '{name}' overlaps the PE headers");
                }
                let raw_end = (raw_offset as usize)
                    .checked_add(raw_size as usize)
                    .ok_or_else(|| anyhow!("section '{name}' has an invalid raw range"))?;
                if raw_end > bytes.len() {
                    bail!("section '{name}' raw data extends past the end of the file");
                }
            }

            let mapped_size = virtual_size.max(raw_size) as usize;
            let mapped_end = (virtual_address as usize)
                .checked_add(mapped_size)
                .ok_or_else(|| anyhow!("section '{name}' has an invalid virtual range"))?;
            if mapped_end > size_of_image {
                bail!("section '{name}' extends past SizeOfImage");
            }

            sections.push(Section {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics: section_characteristics,
            });
        }

        Ok(Self {
            bytes,
            is_64,
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            characteristics,
            sections,
            directories,
        })
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn relocations_present(&self) -> bool {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        directory.size != 0 && directory.virtual_address != 0
    }

    /// Returns the names of all libraries in the regular import directory.
    ///
    /// Delay-loaded libraries are deliberately excluded: they are allowed to
    /// stay lazy, so they must not be preloaded into the target (and some API
    /// set contracts, such as `ext-ms-win32-*`, cannot be loaded manually).
    pub fn imported_modules(&self) -> Result<Vec<String>> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let mut modules: Vec<String> = Vec::new();
        let mut cursor = self
            .rva_to_file_offset(directory.virtual_address as usize)
            .ok_or_else(|| anyhow!("import directory is not file-backed"))?;
        let mut descriptor_count = 0usize;

        loop {
            descriptors_guard(&mut descriptor_count)?;
            if cursor + 20 > self.bytes.len() {
                bail!("import descriptor extends past the end of the file");
            }

            let name_rva = read_u32(self.bytes, cursor + 12)?;
            if name_rva == 0 {
                break;
            }

            let name_offset = self
                .rva_to_file_offset(name_rva as usize)
                .ok_or_else(|| anyhow!("import name RVA 0x{name_rva:x} is out of range"))?;
            let name = display_name(&read_c_string(self.bytes, name_offset)?);
            if !name.is_empty()
                && !modules
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&name))
            {
                modules.push(name);
            }

            cursor += 20;
        }

        Ok(modules)
    }

    /// Returns the names of libraries in the delay-import directory.
    pub fn delay_imported_modules(&self) -> Result<Vec<String>> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let mut modules: Vec<String> = Vec::new();
        let mut cursor = self
            .rva_to_file_offset(directory.virtual_address as usize)
            .ok_or_else(|| anyhow!("delay import directory is not file-backed"))?;
        let mut descriptor_count = 0usize;

        loop {
            descriptors_guard(&mut descriptor_count)?;
            if cursor + 32 > self.bytes.len() {
                bail!("delay import descriptor extends past the end of the file");
            }

            let attributes = read_u32(self.bytes, cursor)?;
            let name_value = read_u32(self.bytes, cursor + 4)?;
            if name_value == 0 {
                break;
            }

            let name_rva = if attributes & 1 != 0 || (name_value as u64) < self.image_base {
                name_value as usize
            } else {
                (name_value as u64 - self.image_base) as usize
            };

            let name_offset = self
                .rva_to_file_offset(name_rva)
                .ok_or_else(|| anyhow!("delay import name RVA 0x{name_rva:x} is out of range"))?;
            let name = display_name(&read_c_string(self.bytes, name_offset)?);
            if !name.is_empty()
                && !modules
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&name))
            {
                modules.push(name);
            }

            cursor += 32;
        }

        Ok(modules)
    }

    fn rva_to_file_offset(&self, rva: usize) -> Option<usize> {
        if rva < self.size_of_headers {
            return (rva < self.bytes.len()).then_some(rva);
        }

        for section in &self.sections {
            let start = section.virtual_address as usize;
            let span = section.virtual_size.max(section.raw_size) as usize;
            if rva >= start && rva < start.saturating_add(span) {
                let delta = rva - start;
                if delta >= section.raw_size as usize {
                    return None;
                }
                let offset = section.raw_offset as usize + delta;
                return (offset < self.bytes.len()).then_some(offset);
            }
        }

        None
    }

    pub fn section_protection(section: &Section) -> u32 {
        let executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;

        match (executable, writable) {
            (true, true) => windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            (true, false) => windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
            (false, true) => windows_sys::Win32::System::Memory::PAGE_READWRITE,
            (false, false) => windows_sys::Win32::System::Memory::PAGE_READONLY,
        }
    }

    fn directory(&self, index: usize) -> DataDirectory {
        self.directories[index]
    }

    fn normalize_rva(&self, value: u64, remote_base: u64) -> Option<usize> {
        let size = self.size_of_image as u64;
        if value >= remote_base && value < remote_base.saturating_add(size) {
            return Some((value - remote_base) as usize);
        }
        if value >= self.image_base && value < self.image_base.saturating_add(size) {
            return Some((value - self.image_base) as usize);
        }
        if value < size {
            return Some(value as usize);
        }
        None
    }

    /// Lays out headers and sections, then applies relocations, imports,
    /// delay imports, the security cookie and TLS bookkeeping.
    pub fn map(&self, remote_base: u64, deferred_delay_imports: &[String]) -> Result<MappedImage> {
        let mut image = vec![0u8; self.size_of_image];

        let headers_len = self.size_of_headers.min(self.bytes.len()).min(image.len());
        image[..headers_len].copy_from_slice(&self.bytes[..headers_len]);

        for section in &self.sections {
            if section.raw_size == 0 {
                continue;
            }
            let src_start = section.raw_offset as usize;
            let src_end = src_start + section.raw_size as usize;
            let dst_start = section.virtual_address as usize;
            let dst_end = dst_start + section.raw_size as usize;

            if src_end > self.bytes.len() || dst_end > image.len() {
                bail!("section '{}' is out of bounds", section.name);
            }
            image[dst_start..dst_end].copy_from_slice(&self.bytes[src_start..src_end]);
        }

        let delta = remote_base.wrapping_sub(self.image_base);
        if delta != 0 {
            self.apply_relocations(&mut image, delta)?;
        }

        let imports = self.resolve_imports(&mut image)?;
        let (delay_imports, skipped_delay_imports) =
            self.resolve_delay_imports(&mut image, remote_base, deferred_delay_imports)?;
        self.initialize_security_cookie(&mut image, remote_base)?;

        let tls_callbacks = self.tls_callbacks(&image, remote_base)?;
        let exception_table = self.exception_table(remote_base);
        let tls_directory = self.directory(IMAGE_DIRECTORY_ENTRY_TLS);
        let has_tls = tls_directory.virtual_address != 0 && tls_directory.size != 0;
        let cfg_targets = self.setup_cfg(&mut image, remote_base)?;
        let uses_cfg = !cfg_targets.is_empty();

        Ok(MappedImage {
            bytes: image,
            entry_point: if self.entry_point_rva == 0 {
                None
            } else {
                Some(remote_base + self.entry_point_rva as u64)
            },
            tls_callbacks,
            exception_table,
            imports,
            delay_imports,
            skipped_delay_imports,
            has_tls,
            uses_cfg,
            cfg_targets,
        })
    }

    /// Collects CFG call targets and, when possible, points the DLL's CFG
    /// check-function pointer at ntdll's real validator.
    fn setup_cfg(&self, image: &mut [u8], remote_base: u64) -> Result<Vec<CfgTarget>> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let load_config = directory.virtual_address as usize;
        if load_config + 4 > image.len() {
            return Ok(Vec::new());
        }
        let load_config_size = read_u32(image, load_config)? as usize;

        let (guard_flags_offset, table_offset, count_offset, check_function_offset, minimum_size) =
            if self.is_64 {
                (144usize, 128usize, 136usize, 112usize, 148usize)
            } else {
                (88usize, 76usize, 80usize, 72usize, 92usize)
            };

        if load_config_size < minimum_size || load_config + minimum_size > image.len() {
            return Ok(Vec::new());
        }

        let guard_flags = read_u32(image, load_config + guard_flags_offset)?;
        if guard_flags & IMAGE_GUARD_CF_INSTRUMENTED == 0
            || guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT == 0
        {
            return Ok(Vec::new());
        }

        let table_va = if self.is_64 {
            read_u64(image, load_config + table_offset)?
        } else {
            read_u32(image, load_config + table_offset)? as u64
        };
        let count = if self.is_64 {
            read_u64(image, load_config + count_offset)?
        } else {
            read_u32(image, load_config + count_offset)? as u64
        };
        if table_va == 0 || count == 0 {
            return Ok(Vec::new());
        }
        if count > 1_000_000 {
            bail!("CFG function table is unreasonably large ({count} entries)");
        }

        let table_rva = self
            .normalize_rva(table_va, remote_base)
            .ok_or_else(|| anyhow!("CFG function table VA 0x{table_va:x} is out of range"))?;
        let extra_bytes = ((guard_flags >> 28) & 0xF) as usize;
        let stride = 4 + extra_bytes;

        let mut targets = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let entry_offset = table_rva
                .checked_add(index * stride)
                .ok_or_else(|| anyhow!("CFG function table overflow"))?;
            let offset = read_u32(image, entry_offset)? as usize;
            targets.push(CfgTarget {
                offset,
                flags: CFG_CALL_TARGET_VALID,
            });
        }

        // The OS loader normally fills this pointer in. Without it, indirect
        // calls may go through an invalid check-function pointer.
        let check_function_va = if self.is_64 {
            read_u64(image, load_config + check_function_offset)?
        } else {
            read_u32(image, load_config + check_function_offset)? as u64
        };
        if check_function_va != 0
            && let Some(validator) = resolve_ntdll_validator()
            && let Some(check_function_rva) = self.normalize_rva(check_function_va, remote_base)
        {
            if self.is_64 {
                write_u64(image, check_function_rva, validator)?;
            } else {
                write_u32(image, check_function_rva, validator as u32)?;
            }
        }

        Ok(targets)
    }

    fn apply_relocations(&self, image: &mut [u8], delta: u64) -> Result<()> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(());
        }

        let start = directory.virtual_address as usize;
        let end = start
            .checked_add(directory.size as usize)
            .ok_or_else(|| anyhow!("relocation directory has an invalid range"))?;
        if end > image.len() {
            bail!("relocation directory extends past the image");
        }

        let mut cursor = start;
        while cursor < end {
            if cursor + 8 > end {
                bail!("truncated relocation block");
            }
            let page_rva = read_u32(image, cursor)? as usize;
            let block_size = read_u32(image, cursor + 4)? as usize;
            if block_size == 0 {
                break;
            }
            if block_size < 8 || cursor + block_size > end {
                bail!("invalid relocation block size 0x{block_size:x}");
            }

            let entry_count = (block_size - 8) / 2;
            for index in 0..entry_count {
                let entry = read_u16(image, cursor + 8 + index * 2)?;
                let relocation_type = entry >> 12;
                let offset = (entry & 0x0fff) as usize;
                let target = page_rva
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("relocation target overflow"))?;

                match relocation_type {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_HIGHLOW => {
                        let value = read_u32(image, target)?;
                        write_u32(image, target, value.wrapping_add(delta as u32))?;
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        if !self.is_64 {
                            bail!("DIR64 relocation found in a 32-bit image");
                        }
                        let value = read_u64(image, target)?;
                        write_u64(image, target, value.wrapping_add(delta))?;
                    }
                    other => bail!("unsupported relocation type {other}"),
                }
            }

            cursor += block_size;
        }

        Ok(())
    }

    fn resolve_imports(&self, image: &mut [u8]) -> Result<usize> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(0);
        }

        let thunk_size = if self.is_64 { 8 } else { 4 };
        let ordinal_flag = if self.is_64 {
            IMAGE_ORDINAL_FLAG64
        } else {
            IMAGE_ORDINAL_FLAG32
        };

        let mut cursor = directory.virtual_address as usize;
        let mut resolved = 0usize;
        let mut descriptor_count = 0usize;

        loop {
            descriptors_guard(&mut descriptor_count)?;
            if cursor + 20 > image.len() {
                bail!("import descriptor extends past the image");
            }

            let original_first_thunk = read_u32(image, cursor)?;
            let name_rva = read_u32(image, cursor + 12)?;
            let first_thunk = read_u32(image, cursor + 16)?;
            if name_rva == 0 {
                break;
            }
            if first_thunk == 0 {
                bail!("import descriptor has no FirstThunk");
            }

            let module_name = read_c_string(image, name_rva as usize)?;
            let module = unsafe { LoadLibraryA(module_name.as_ptr()) };
            if module.is_null() {
                bail!(
                    "failed to load imported library '{}' in the injector process",
                    display_name(&module_name)
                );
            }

            let int_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let mut int_offset = int_rva as usize;
            let mut iat_offset = first_thunk as usize;

            loop {
                let thunk = if self.is_64 {
                    read_u64(image, int_offset)?
                } else {
                    read_u32(image, int_offset)? as u64
                };
                if thunk == 0 {
                    break;
                }

                let address = if thunk & ordinal_flag != 0 {
                    let ordinal = (thunk & 0xffff) as u16;
                    unsafe { GetProcAddress(module, ordinal as usize as *const u8) }.ok_or_else(
                        || {
                            anyhow!(
                                "import '{}' ordinal {ordinal} was not found",
                                display_name(&module_name)
                            )
                        },
                    )? as usize
                } else {
                    let name_offset = ((thunk & !ordinal_flag) as usize)
                        .checked_add(2)
                        .ok_or_else(|| anyhow!("import name RVA overflow"))?;
                    let function_name = read_c_string(image, name_offset)?;
                    unsafe { GetProcAddress(module, function_name.as_ptr()) }.ok_or_else(|| {
                        anyhow!(
                            "import '{}!{}' was not found",
                            display_name(&module_name),
                            display_name(&function_name)
                        )
                    })? as usize
                };

                if self.is_64 {
                    write_u64(image, iat_offset, address as u64)?;
                } else {
                    write_u32(image, iat_offset, address as u32)?;
                }

                resolved += 1;
                int_offset = int_offset
                    .checked_add(thunk_size)
                    .ok_or_else(|| anyhow!("import table offset overflow"))?;
                iat_offset = iat_offset
                    .checked_add(thunk_size)
                    .ok_or_else(|| anyhow!("import address table offset overflow"))?;
            }

            cursor += 20;
        }

        Ok(resolved)
    }

    /// Resolves delay imports eagerly where possible.
    ///
    /// A descriptor that cannot be prepared is left untouched, so the DLL's
    /// original delay-load thunks still resolve it on first use. This is
    /// important for API set contracts such as `ext-ms-win32-*` that cannot be
    /// loaded with `LoadLibraryA` directly.
    fn resolve_delay_imports(
        &self,
        image: &mut [u8],
        remote_base: u64,
        deferred_delay_imports: &[String],
    ) -> Result<(usize, usize)> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok((0, 0));
        }

        let thunk_size = if self.is_64 { 8 } else { 4 };
        let ordinal_flag = if self.is_64 {
            IMAGE_ORDINAL_FLAG64
        } else {
            IMAGE_ORDINAL_FLAG32
        };

        let mut cursor = directory.virtual_address as usize;
        let mut resolved = 0usize;
        let mut skipped = 0usize;
        let mut descriptor_count = 0usize;

        loop {
            descriptors_guard(&mut descriptor_count)?;
            if cursor + 32 > image.len() {
                bail!("delay import descriptor extends past the image");
            }

            let attributes = read_u32(image, cursor)?;
            let name_value = read_u32(image, cursor + 4)?;
            if name_value == 0 {
                break;
            }
            let fields_are_rvas = attributes & 1 != 0;
            let module_handle_value = read_u32(image, cursor + 8)?;
            let iat_value = read_u32(image, cursor + 12)?;
            let int_value = read_u32(image, cursor + 16)?;

            let normalize = |value: u32| -> Option<usize> {
                if fields_are_rvas {
                    Some(value as usize)
                } else {
                    self.normalize_rva(value as u64, remote_base)
                }
            };

            let Some(name_rva) = normalize(name_value) else {
                skipped += 1;
                cursor += 32;
                continue;
            };
            let Ok(module_name) = read_c_string(image, name_rva) else {
                skipped += 1;
                cursor += 32;
                continue;
            };
            if deferred_delay_imports
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&display_name(&module_name)))
            {
                skipped += 1;
                cursor += 32;
                continue;
            }
            let module = unsafe { LoadLibraryA(module_name.as_ptr()) };
            if module.is_null() {
                skipped += 1;
                cursor += 32;
                continue;
            }

            let mut pending: Vec<(usize, usize)> = Vec::new();
            let mut failed = false;

            if int_value != 0 && iat_value != 0 {
                let offsets = (normalize(int_value), normalize(iat_value));
                let (Some(mut int_offset), Some(mut iat_offset)) = offsets else {
                    skipped += 1;
                    cursor += 32;
                    continue;
                };

                while !failed {
                    let thunk = if self.is_64 {
                        match read_u64(image, int_offset) {
                            Ok(value) => value,
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    } else {
                        match read_u32(image, int_offset) {
                            Ok(value) => value as u64,
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    };
                    if thunk == 0 {
                        break;
                    }

                    let address = if thunk & ordinal_flag != 0 {
                        let ordinal = (thunk & 0xffff) as u16;
                        unsafe { GetProcAddress(module, ordinal as usize as *const u8) }
                            .map(|function| function as usize)
                    } else {
                        let raw = thunk & !ordinal_flag;
                        self.normalize_rva(raw, remote_base).and_then(|name_rva| {
                            let name_offset = name_rva.checked_add(2)?;
                            let function_name = read_c_string(image, name_offset).ok()?;
                            unsafe { GetProcAddress(module, function_name.as_ptr()) }
                                .map(|function| function as usize)
                        })
                    };

                    let Some(address) = address else {
                        failed = true;
                        break;
                    };

                    pending.push((iat_offset, address));
                    int_offset = match int_offset.checked_add(thunk_size) {
                        Some(value) => value,
                        None => {
                            failed = true;
                            break;
                        }
                    };
                    iat_offset = match iat_offset.checked_add(thunk_size) {
                        Some(value) => value,
                        None => {
                            failed = true;
                            break;
                        }
                    };
                }
            }

            if failed {
                skipped += 1;
                cursor += 32;
                continue;
            }

            for (iat_offset, address) in pending {
                if self.is_64 {
                    write_u64(image, iat_offset, address as u64)?;
                } else {
                    write_u32(image, iat_offset, address as u32)?;
                }
                resolved += 1;
            }

            if module_handle_value != 0
                && let Some(module_handle_offset) = normalize(module_handle_value)
            {
                if self.is_64 {
                    write_u64(image, module_handle_offset, module as u64)?;
                } else {
                    write_u32(image, module_handle_offset, module as u32)?;
                }
            }

            cursor += 32;
        }

        Ok((resolved, skipped))
    }

    fn initialize_security_cookie(&self, image: &mut [u8], remote_base: u64) -> Result<()> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(());
        }

        let load_config = directory.virtual_address as usize;
        if load_config + 4 > image.len() {
            return Ok(());
        }
        let load_config_size = read_u32(image, load_config)? as usize;
        let (cookie_offset, cookie_size) = if self.is_64 {
            (96usize, 8usize)
        } else {
            (60, 4)
        };

        if load_config_size < cookie_offset + cookie_size
            || load_config + cookie_offset + cookie_size > image.len()
        {
            return Ok(());
        }

        let cookie_va = if self.is_64 {
            read_u64(image, load_config + cookie_offset)?
        } else {
            read_u32(image, load_config + cookie_offset)? as u64
        };
        if cookie_va == 0 {
            return Ok(());
        }

        let cookie_rva = self
            .normalize_rva(cookie_va, remote_base)
            .ok_or_else(|| anyhow!("security cookie VA 0x{cookie_va:x} is out of range"))?;
        let cookie = random_cookie(self.is_64);

        if self.is_64 {
            write_u64(image, cookie_rva, cookie)?;
        } else {
            write_u32(image, cookie_rva, cookie as u32)?;
        }

        Ok(())
    }

    fn tls_callbacks(&self, image: &[u8], remote_base: u64) -> Result<Vec<u64>> {
        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_TLS);
        if directory.size == 0 || directory.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let tls = directory.virtual_address as usize;
        let (callbacks_offset, pointer_size) = if self.is_64 {
            (24usize, 8usize)
        } else {
            (12, 4)
        };
        if tls + callbacks_offset + pointer_size > image.len() {
            return Ok(Vec::new());
        }

        let callbacks_va = if self.is_64 {
            read_u64(image, tls + callbacks_offset)?
        } else {
            read_u32(image, tls + callbacks_offset)? as u64
        };
        if callbacks_va == 0 {
            return Ok(Vec::new());
        }

        let mut cursor = self
            .normalize_rva(callbacks_va, remote_base)
            .ok_or_else(|| anyhow!("TLS callback array VA 0x{callbacks_va:x} is out of range"))?;

        let delta = remote_base.wrapping_sub(self.image_base);
        let mut callbacks = Vec::new();

        loop {
            if callbacks.len() >= 4096 {
                bail!("too many TLS callbacks");
            }
            let value = if self.is_64 {
                read_u64(image, cursor)?
            } else {
                read_u32(image, cursor)? as u64
            };
            if value == 0 {
                break;
            }

            // TLS callback entries are VAs. They are usually already relocated,
            // but accept the preferred base too for images whose relocation
            // table does not cover the TLS directory.
            let callback = if value >= remote_base
                && value < remote_base.saturating_add(self.size_of_image as u64)
            {
                value
            } else if value >= self.image_base
                && value < self.image_base.saturating_add(self.size_of_image as u64)
            {
                value.wrapping_add(delta)
            } else {
                bail!("TLS callback address 0x{value:x} is outside the image");
            };

            callbacks.push(callback);
            cursor = cursor
                .checked_add(pointer_size)
                .ok_or_else(|| anyhow!("TLS callback array overflow"))?;
        }

        Ok(callbacks)
    }

    fn exception_table(&self, remote_base: u64) -> Option<(u64, u32)> {
        if !self.is_64 {
            return None;
        }

        let directory = self.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        if directory.size == 0 || directory.virtual_address == 0 {
            return None;
        }

        let count = directory.size / 12;
        if count == 0 {
            return None;
        }

        Some((remote_base + directory.virtual_address as u64, count))
    }
}

fn descriptors_guard(count: &mut usize) -> Result<()> {
    *count += 1;
    if *count > 4096 {
        bail!("too many import descriptors");
    }
    Ok(())
}

fn resolve_ntdll_validator() -> Option<u64> {
    let module = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr() as *const u8) };
    if module.is_null() {
        return None;
    }
    let function =
        unsafe { GetProcAddress(module, c"LdrpValidateUserCallTarget".as_ptr() as *const u8) }?;
    Some(function as usize as u64)
}

fn display_name(name_with_nul: &[u8]) -> String {
    let name = name_with_nul.strip_suffix(&[0]).unwrap_or(name_with_nul);
    String::from_utf8_lossy(name).into_owned()
}

fn read_c_string(bytes: &[u8], offset: usize) -> Result<Vec<u8>> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| anyhow!("string RVA 0x{offset:x} is out of range"))?;
    let length = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| anyhow!("unterminated string at RVA 0x{offset:x}"))?;
    Ok(tail[..=length].to_vec())
}

fn random_cookie(is_64: bool) -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    hasher.write_u64(now);
    hasher.write_usize(&hasher as *const _ as usize);
    let mut value = hasher.finish();

    if is_64 {
        if value == 0 || value == 0x0000_2b99_2ddf_a232 {
            value ^= 0xdead_beef_cafe_babe;
        }
    } else {
        value &= 0xffff_ffff;
        if value == 0 || value == 0xbb40_e64e {
            value ^= 0xdead_beef;
        }
    }

    value
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slot = slice_at(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([slot[0], slot[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slot = slice_at(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let slot = slice_at(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        slot[0], slot[1], slot[2], slot[3], slot[4], slot[5], slot[6], slot[7],
    ]))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let slot = slice_at_mut(bytes, offset, 4)?;
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let slot = slice_at_mut(bytes, offset, 8)?;
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn slice_at(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("offset overflow at 0x{offset:x}"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| anyhow!("PE is truncated at offset 0x{offset:x}"))
}

fn slice_at_mut(bytes: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("offset overflow at 0x{offset:x}"))?;
    bytes
        .get_mut(offset..end)
        .ok_or_else(|| anyhow!("PE is truncated at offset 0x{offset:x}"))
}
