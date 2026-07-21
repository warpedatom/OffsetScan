//! PE header/section/import parsing — mirrors `Get-OffsetPEInfo` (OffsetInspect.PEInfo).
//!
//! Parity notes vs OffsetInspect:
//!  - `Machine` is a DISPLAY string ("x64 (AMD64)", ...), not the raw hex id.
//!  - `IsPE32Plus` (not "Is64Bit").
//!  - `Imports` is grouped: one { Dll, Functions[] } per DLL, in directory order.
//!  - Imphash = MD5 of comma-joined lowercased `libbase.func` (libbase = dll name with
//!    .dll/.ocx/.sys stripped), per imported function in directory order; ordinal-only
//!    imports render as `ord<N>`. Null (None) when there are no imports.
//!  - `ResourceSize` is the PE data-directory #2 (Resource) SIZE field — a single u32,
//!    NOT a resource-tree walk.
//!  - A PE section object carries NO entropy field.

use crate::schema::{Import, PeInfo, Section};
use goblin::pe::PE;
use md5::{Digest, Md5};

fn machine_name(machine: u16) -> String {
    match machine {
        0x8664 => "x64 (AMD64)".to_string(),
        0x014C => "x86 (I386)".to_string(),
        0xAA64 => "ARM64".to_string(),
        0x01C0 => "ARM".to_string(),
        0x01C4 => "ARMNT".to_string(),
        other => format!("0x{:04X}", other),
    }
}

fn strip_lib_ext(dll_lower: &str) -> &str {
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(base) = dll_lower.strip_suffix(ext) {
            return base;
        }
    }
    dll_lower
}

pub fn parse_pe(data: &[u8], file_path: &str) -> Result<PeInfo, String> {
    let pe = PE::parse(data).map_err(|e| format!("PE parse error: {e}"))?;

    let machine = machine_name(pe.header.coff_header.machine);

    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| Section {
            name: s.name().unwrap_or("?").to_string(),
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address,
            size_of_raw_data: s.size_of_raw_data,
            pointer_to_raw_data: s.pointer_to_raw_data,
        })
        .collect();

    // Group imports by DLL (first-seen order) and build the imphash entry list in
    // directory order at the same time.
    let mut imports: Vec<Import> = Vec::new();
    let mut imphash_entries: Vec<String> = Vec::new();
    for import in &pe.imports {
        let dll_display = import.dll.to_string();
        let dll_lower = import.dll.to_lowercase();
        let lib_base = strip_lib_ext(&dll_lower).to_string();
        // goblin represents an ordinal-only import with a SYNTHESIZED name
        // ("ORDINAL <n>"), not an empty one, so detect both forms. For ordinals imported
        // from ws2_32/wsock32/oleaut32, resolve to the real function name exactly as
        // pefile/VirusTotal do (so the imphash correlates with threat intel); any other
        // ordinal renders "ord<n>". The resolved name is lowercased in the table, so the
        // imphash and display strings are identical.
        let by_ordinal = import.name.is_empty() || import.name.starts_with("ORDINAL ");
        let func = if by_ordinal {
            crate::ordinals::special_ordinal_name(&dll_lower, import.ordinal)
                .map(str::to_string)
                .unwrap_or_else(|| format!("ord{}", import.ordinal))
        } else {
            import.name.to_lowercase()
        };
        imphash_entries.push(format!("{lib_base}.{func}"));

        let func_display = if by_ordinal {
            func.clone()
        } else {
            import.name.to_string()
        };
        match imports.iter_mut().find(|i| i.dll == dll_display) {
            Some(existing) => existing.functions.push(func_display),
            None => imports.push(Import {
                dll: dll_display,
                functions: vec![func_display],
            }),
        }
    }

    let imp_hash = if imphash_entries.is_empty() {
        None
    } else {
        let mut hasher = Md5::new();
        hasher.update(imphash_entries.join(",").as_bytes());
        Some(format!("{:x}", hasher.finalize()))
    };

    // Resource-directory size (PE data directory index 2). VERIFY goblin API surface:
    // recent goblin exposes optional_header.data_directories.get_resource_table().
    let resource_size = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|oh| oh.data_directories.get_resource_table())
        .map(|d| d.size)
        .unwrap_or(0);

    // Overlay = bytes appended after the last section's raw data.
    let last_section_end = pe
        .sections
        .iter()
        .map(|s| (s.pointer_to_raw_data as u64) + (s.size_of_raw_data as u64))
        .max()
        .unwrap_or(0);
    let file_len = data.len() as u64;
    let overlay_size = file_len.saturating_sub(last_section_end);
    let has_overlay = overlay_size > 0;
    let overlay_offset = if has_overlay {
        Some(last_section_end)
    } else {
        None
    };

    Ok(PeInfo {
        file: file_path.to_string(),
        file_size: file_len,
        machine,
        is_pe32_plus: pe.is_64,
        entry_point_rva: pe.entry as u32,
        entry_point_hex: format!("0x{:X}", pe.entry),
        image_base: pe.image_base as u64,
        section_count: sections.len() as u32,
        imported_dll_count: imports.len() as u32,
        sections,
        imports,
        imp_hash,
        resource_size,
        has_overlay,
        overlay_offset,
        overlay_size,
        mapped_offset: None, // populated only when a caller passes an explicit offset
        mapped_section: None,
        warnings: Vec::new(),
    })
}

/// Map a byte offset to the containing PE section name (".text", ...), if any.
/// Wired to the `pe --offset` flag.
pub fn offset_to_section(data: &[u8], offset: u64) -> Result<Option<String>, String> {
    let pe = PE::parse(data).map_err(|e| format!("PE parse error: {e}"))?;
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as u64;
        let end = start + section.size_of_raw_data as u64;
        if section.size_of_raw_data > 0 && offset >= start && offset < end {
            return Ok(Some(section.name().unwrap_or("?").to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_known_library_extensions() {
        assert_eq!(strip_lib_ext("kernel32.dll"), "kernel32");
        assert_eq!(strip_lib_ext("comctl32.ocx"), "comctl32");
        assert_eq!(strip_lib_ext("driver.sys"), "driver");
        assert_eq!(strip_lib_ext("noextension"), "noextension");
    }

    #[test]
    fn maps_known_machine_ids_to_display_strings() {
        assert_eq!(machine_name(0x8664), "x64 (AMD64)");
        assert_eq!(machine_name(0x014C), "x86 (I386)");
        assert_eq!(machine_name(0xAA64), "ARM64");
        assert!(machine_name(0x1234).starts_with("0x"));
    }

    #[test]
    fn rejects_a_non_pe_buffer() {
        assert!(parse_pe(b"this is not a PE image at all", "sample").is_err());
    }
}
