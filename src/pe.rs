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

/// Parse a PE, preferring goblin's strict full-structure validation. If that rejects the
/// file, fall back to a lenient header-salvage parse that mirrors OffsetInspect's
/// `ConvertTo-OIPEImage`: a structurally-damaged sample (e.g. a truncated or carved
/// binary whose headers are intact) still yields machine/sections/imphash, matching
/// OffsetInspect instead of giving up. Valid PEs always take the goblin path, so their
/// output is unchanged.
pub fn parse_pe(data: &[u8], file_path: &str) -> Result<PeInfo, String> {
    match parse_pe_strict(data, file_path) {
        Ok(info) => Ok(info),
        Err(_) => parse_pe_lenient(data, file_path),
    }
}

fn parse_pe_strict(data: &[u8], file_path: &str) -> Result<PeInfo, String> {
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

fn rd_u16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn rd_u64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a NUL-terminated string decoded as ASCII (bytes >= 0x80 become '?'), matching
/// OffsetInspect's `Read-OINullTerminatedAscii` (`[Text.Encoding]::ASCII.GetString`).
fn read_ascii_cstr(d: &[u8], off: usize, max: usize) -> String {
    if off >= d.len() {
        return String::new();
    }
    let end = (off + max).min(d.len());
    let mut s = String::new();
    for &b in &d[off..end] {
        if b == 0 {
            break;
        }
        s.push(if b < 0x80 { b as char } else { '?' });
    }
    s
}

/// Map an RVA to a file offset via the section table (max of virtual/raw size for the
/// span), mirroring `ConvertFrom-OIRvaToOffset`.
fn rva_to_offset(sections: &[Section], rva: u64) -> Option<u64> {
    for s in sections {
        let va = s.virtual_address as u64;
        let span = std::cmp::max(s.virtual_size as u64, s.size_of_raw_data as u64);
        if rva >= va && rva < va + span {
            return Some(rva - va + s.pointer_to_raw_data as u64);
        }
    }
    None
}

/// Lenient header-salvage parse mirroring OffsetInspect's `ConvertTo-OIPEImage`. Header and
/// section table are read from the first 64 KiB (as OffsetInspect does); import data is read
/// from the full file. Returns Err on the same conditions OffsetInspect throws on (missing
/// MZ/PE signatures, truncated fixed header fields, or a section table not fully present, so
/// a bogus 65535-section count is rejected rather than salvaged).
fn parse_pe_lenient(data: &[u8], file_path: &str) -> Result<PeInfo, String> {
    let hdr = &data[..data.len().min(0x10000)];

    if rd_u16(hdr, 0) != Some(0x5A4D) {
        return Err("Not a PE image: missing MZ (DOS) signature.".into());
    }
    let pe_off = rd_u32(hdr, 0x3C).ok_or("truncated DOS header")? as usize;
    if pe_off == 0 || hdr.get(pe_off..pe_off + 4) != Some(&[0x50, 0x45, 0x00, 0x00]) {
        return Err("Not a PE image: missing PE signature.".into());
    }

    let coff = pe_off + 4;
    let machine_id = rd_u16(hdr, coff).ok_or("truncated COFF header")?;
    let section_count = rd_u16(hdr, coff + 2).ok_or("truncated COFF header")?;
    let opt_hdr_size = rd_u16(hdr, coff + 16).ok_or("truncated COFF header")? as usize;

    let opt = coff + 20;
    let magic = rd_u16(hdr, opt).ok_or("truncated optional header")?;
    let is_pe32_plus = magic == 0x20B;
    let entry_point_rva = rd_u32(hdr, opt + 16).ok_or("truncated optional header")?;
    let image_base = if is_pe32_plus {
        rd_u64(hdr, opt + 24).ok_or("truncated optional header")?
    } else {
        rd_u32(hdr, opt + 28).ok_or("truncated optional header")? as u64
    };

    // Data directories: index 1 = import, index 2 = resource. NumberOfRvaAndSizes sits in
    // the u32 immediately before the directory array.
    let dd_base = if is_pe32_plus { opt + 112 } else { opt + 96 };
    let rva_count = rd_u32(hdr, dd_base.saturating_sub(4)).unwrap_or(0);
    let read_dd = |index: usize| -> (u32, u32) {
        if (index as u32) < rva_count {
            let off = dd_base + index * 8;
            if let (Some(rva), Some(size)) = (rd_u32(hdr, off), rd_u32(hdr, off + 4)) {
                return (rva, size);
            }
        }
        (0, 0)
    };
    let (import_rva, _) = read_dd(1);
    let (_, resource_size) = read_dd(2);

    let sec_table = opt + opt_hdr_size;
    let mut sections = Vec::new();
    for i in 0..section_count as usize {
        let e = sec_table + i * 40;
        if e + 40 > hdr.len() {
            return Err("The header buffer is truncated before the section table.".into());
        }
        sections.push(Section {
            name: read_ascii_cstr(hdr, e, 8),
            virtual_size: rd_u32(hdr, e + 8).unwrap_or(0),
            virtual_address: rd_u32(hdr, e + 12).unwrap_or(0),
            size_of_raw_data: rd_u32(hdr, e + 16).unwrap_or(0),
            pointer_to_raw_data: rd_u32(hdr, e + 20).unwrap_or(0),
        });
    }

    let (imports, imp_hash) = lenient_imports(data, &sections, import_rva as u64, is_pe32_plus);

    let last_end = sections
        .iter()
        .filter(|s| s.size_of_raw_data > 0)
        .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
        .max()
        .unwrap_or(0);
    let file_len = data.len() as u64;
    let overlay_size = file_len.saturating_sub(last_end);
    let has_overlay = overlay_size > 0;

    Ok(PeInfo {
        file: file_path.to_string(),
        file_size: file_len,
        machine: machine_name(machine_id),
        is_pe32_plus,
        entry_point_rva,
        entry_point_hex: format!("0x{:X}", entry_point_rva),
        image_base,
        section_count: sections.len() as u32,
        imported_dll_count: imports.len() as u32,
        sections,
        imports,
        imp_hash,
        resource_size,
        has_overlay,
        overlay_offset: if has_overlay { Some(last_end) } else { None },
        overlay_size,
        mapped_offset: None,
        mapped_section: None,
        warnings: Vec::new(),
    })
}

/// Best-effort import walk for the lenient path, mirroring `Get-OIPEImport` (including the
/// special-library ordinal resolution). A truncated or unmappable import table yields no
/// imports and a null imphash rather than failing the whole parse.
fn lenient_imports(
    data: &[u8],
    sections: &[Section],
    import_rva: u64,
    is_pe32_plus: bool,
) -> (Vec<Import>, Option<String>) {
    let mut imports = Vec::new();
    let mut imphash_entries: Vec<String> = Vec::new();
    if import_rva == 0 {
        return (imports, None);
    }
    let desc_off = match rva_to_offset(sections, import_rva) {
        Some(o) => o as usize,
        None => return (imports, None),
    };
    let ptr_size = if is_pe32_plus { 8usize } else { 4 };
    let ordinal_flag: u64 = if is_pe32_plus {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    for di in 0..4096usize {
        let base = desc_off + di * 20;
        let oft = match rd_u32(data, base) {
            Some(v) => v,
            None => break,
        };
        let name_rva = rd_u32(data, base + 12).unwrap_or(0);
        let first_thunk = rd_u32(data, base + 16).unwrap_or(0);
        if oft == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let lib_name = rva_to_offset(sections, name_rva as u64)
            .map(|o| read_ascii_cstr(data, o as usize, 256))
            .unwrap_or_default();
        let lib_lower = lib_name.to_lowercase();
        let lib_base = strip_lib_ext(&lib_lower).to_string();

        let mut functions = Vec::new();
        let thunk_rva = if oft != 0 { oft } else { first_thunk };
        if let Some(to) = rva_to_offset(sections, thunk_rva as u64) {
            for ti in 0..100_000usize {
                let toff = to as usize + ti * ptr_size;
                let tv = if is_pe32_plus {
                    match rd_u64(data, toff) {
                        Some(v) => v,
                        None => break,
                    }
                } else {
                    match rd_u32(data, toff) {
                        Some(v) => v as u64,
                        None => break,
                    }
                };
                if tv == 0 {
                    break;
                }
                let func = if tv & ordinal_flag != 0 {
                    let ord = (tv & 0xFFFF) as u16;
                    crate::ordinals::special_ordinal_name(&lib_lower, ord)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ord{}", ord))
                } else {
                    rva_to_offset(sections, tv & 0xFFFF_FFFF)
                        .map(|bn| read_ascii_cstr(data, bn as usize + 2, 256))
                        .unwrap_or_default()
                };
                if !func.is_empty() {
                    imphash_entries.push(format!("{}.{}", lib_base, func.to_lowercase()));
                    functions.push(func);
                }
            }
        }
        imports.push(Import {
            dll: lib_name,
            functions,
        });
    }

    let imp_hash = if imphash_entries.is_empty() {
        None
    } else {
        let mut hasher = Md5::new();
        hasher.update(imphash_entries.join(",").as_bytes());
        Some(format!("{:x}", hasher.finalize()))
    };
    (imports, imp_hash)
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

    /// Build a minimal PE32+ header (MZ + PE + COFF + optional header + one section),
    /// no section data. Enough for the lenient parser to salvage.
    fn minimal_pe32plus_header(section_count: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0] = 0x4D;
        b[1] = 0x5A; // MZ
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        b[0x80] = 0x50;
        b[0x81] = 0x45; // PE\0\0
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x64
        b[0x86..0x88].copy_from_slice(&section_count.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        b[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        b[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
        let sec = 0x188; // opt(0x98) + SizeOfOptionalHeader(0xF0)
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        b
    }

    #[test]
    fn lenient_parse_salvages_a_header_only_pe() {
        // A truncated/carved sample whose headers are intact: goblin rejects it, but the
        // lenient fallback recovers machine/sections, matching OffsetInspect's salvage.
        let info = parse_pe_lenient(&minimal_pe32plus_header(1), "x")
            .expect("lenient parse should salvage a valid header");
        assert_eq!(info.machine, "x64 (AMD64)");
        assert!(info.is_pe32_plus);
        assert_eq!(info.section_count, 1);
        assert_eq!(info.sections[0].name, ".text");
        assert_eq!(info.entry_point_rva, 0x1000);
        assert!(info.imp_hash.is_none()); // no import directory
    }

    #[test]
    fn lenient_parse_rejects_non_pe_and_unfittable_section_counts() {
        assert!(parse_pe_lenient(b"not a pe", "x").is_err());
        // A 65535-section count that cannot fit the buffer must be rejected, not salvaged,
        // matching OffsetInspect's $requireBytes behavior.
        assert!(parse_pe_lenient(&minimal_pe32plus_header(0xFFFF), "x").is_err());
    }
}
