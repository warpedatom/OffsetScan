//! Consolidated indicator panel — mirrors `Get-OffsetIOC` (OffsetInspect.IOC).
//!
//! Parity notes vs OffsetInspect:
//!  - FLAT shape: PE fields (Machine/ImpHash/ImportedDllCount/HasOverlay/OverlaySize)
//!    are inlined as nullable fields, NOT a nested PeInfo object.
//!  - OverallEntropy + HighEntropyWindows come from a 256-byte-window entropy pass
//!    at the 7.0 high threshold.
//!  - PrintableStringCount counts BOTH ASCII and UTF-16LE strings at minimum length 6.

use crate::entropy::build_entropy_result;
use crate::pe::parse_pe;
use crate::schema::Ioc;
use crate::strings::{extract_ascii_strings, extract_utf16le_strings};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn build_ioc_panel(data: &[u8], file_path: &str) -> Ioc {
    let md5 = {
        let mut h = Md5::default();
        Digest::update(&mut h, data);
        format!("{:x}", Digest::finalize(h))
    };
    let sha1 = {
        let mut h = Sha1::default();
        Digest::update(&mut h, data);
        format!("{:x}", Digest::finalize(h))
    };
    let sha256 = {
        let mut h = Sha256::default();
        Digest::update(&mut h, data);
        format!("{:x}", Digest::finalize(h))
    };

    let entropy = build_entropy_result(data, file_path, 256, 7.0);
    let printable_string_count =
        (extract_ascii_strings(data, 6).len() + extract_utf16le_strings(data, 6).len()) as u32;

    let pe = parse_pe(data, file_path).ok();

    Ioc {
        file: file_path.to_string(),
        file_size: data.len() as u64,
        md5,
        sha1,
        sha256,
        overall_entropy: entropy.overall_entropy,
        high_entropy_windows: entropy.high_window_count,
        printable_string_count,
        is_pe: pe.is_some(),
        machine: pe.as_ref().map(|p| p.machine.clone()),
        imp_hash: pe.as_ref().and_then(|p| p.imp_hash.clone()),
        imported_dll_count: pe.as_ref().map(|p| p.imported_dll_count),
        has_overlay: pe.as_ref().map(|p| p.has_overlay),
        overlay_size: pe.as_ref().map(|p| p.overlay_size),
    }
}
