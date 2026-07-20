//! Schema — the JSON contract with OffsetInspect (PowerShell).
//!
//! Field names/casing verified FIELD-FOR-FIELD against the actual OffsetInspect
//! 3.0.0 result objects (Get-OffsetPEInfo, Get-OffsetEntropy, Get-OffsetString,
//! Get-OffsetIOC) and docs/OUTPUT-SCHEMA.md — not the README.
//!
//! PowerShell PSCustomObject property names are case-preserving, and consumers
//! match on exact casing. `rename_all = "PascalCase"` handles most fields, but it
//! turns `md5`/`sha1`/`sha256`/`is_pe`/`is_pe32_plus` into `Md5`/`Sha1`/`IsPe`/... —
//! WRONG. Those carry an explicit `#[serde(rename = ...)]` to match `MD5`/`SHA1`/
//! `SHA256`/`IsPE`/`IsPE32Plus`.
//!
//! OffsetScan is a static engine: it does NOT emit `OffsetInspect.Result` or
//! `ThreatScanResult` (those come from Invoke-OffsetInspect / Invoke-OffsetThreatScan,
//! which are Windows-only AMSI/Defender paths). If you later ingest/merge those,
//! model them separately against docs/OUTPUT-SCHEMA.md.

// The ingestion structs below (OffsetResult / ThreatScanResult / BoundaryValidation /
// ProbeLogEntry) are deserialize-only — nothing in the binary constructs them yet.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `Get-OffsetPEInfo` -> OffsetInspect.PEInfo
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PeInfo {
    pub file: String,
    pub file_size: u64,
    pub machine: String, // display string, e.g. "x64 (AMD64)"
    #[serde(rename = "IsPE32Plus")]
    pub is_pe32_plus: bool,
    pub entry_point_rva: u32,
    pub entry_point_hex: String,
    pub image_base: u64,
    pub section_count: u32,
    pub sections: Vec<Section>,
    pub imported_dll_count: u32,
    pub imports: Vec<Import>,
    pub imp_hash: Option<String>,
    pub resource_size: u32, // PE data-directory #2 (Resource) size field — NOT a tree walk
    pub has_overlay: bool,
    pub overlay_offset: Option<u64>,
    pub overlay_size: u64, // 0 when no overlay (not null)
    pub mapped_offset: Option<u64>,
    pub mapped_section: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    // NOTE: OffsetInspect's Section object has NO per-section entropy field.
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Import {
    pub dll: String,
    pub functions: Vec<String>,
}

/// `Get-OffsetEntropy` -> OffsetInspect.EntropyResult (a wrapper object, not a bare array)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EntropyResult {
    pub file: String,
    pub file_size: u64,
    pub window_size: u32,
    pub window_count: u32,
    pub overall_entropy: f64,
    pub high_entropy_threshold: f64,
    pub high_window_count: u32,
    pub windows: Vec<EntropyWindow>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EntropyWindow {
    pub index: u32,
    pub start_offset: u64,
    pub start_hex: String,
    pub end_offset: u64, // INCLUSIVE last byte: start + length - 1
    pub length: u32,
    pub entropy: f64, // rounded to 6 dp
    pub is_high: bool,
}

/// `Get-OffsetString` record
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct StringHit {
    pub offset: u64,
    pub offset_hex: String,
    pub encoding: String, // exactly "Ascii" | "Unicode"
    pub length: u32,
    pub value: String,
}

/// `Get-OffsetIOC` -> OffsetInspect.IOC  (FLAT — PE fields are inlined, not a nested object)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Ioc {
    pub file: String,
    pub file_size: u64,
    #[serde(rename = "MD5")]
    pub md5: String,
    #[serde(rename = "SHA1")]
    pub sha1: String,
    #[serde(rename = "SHA256")]
    pub sha256: String,
    pub overall_entropy: f64,
    pub high_entropy_windows: u32,
    pub printable_string_count: u32,
    #[serde(rename = "IsPE")]
    pub is_pe: bool,
    // The following five are null when IsPE == false:
    pub machine: Option<String>,
    pub imp_hash: Option<String>,
    pub imported_dll_count: Option<u32>,
    pub has_overlay: Option<bool>,
    pub overlay_size: Option<u64>,
}

// ---------------------------------------------------------------------------
// INGESTION-ONLY. OffsetScan does NOT produce these. They are the shapes emitted
// by Invoke-OffsetInspect (`OffsetInspect.Result`) and Invoke-OffsetThreatScan
// (`OffsetInspect.ThreatScanResult`, Windows-only AMSI/Defender). Modeled here so
// a consumer/merge layer can deserialize OffsetInspect JSON — e.g. for feeding
// Export-OffsetThreatReport or Compare-OffsetThreatResult. Verified against
// docs/OUTPUT-SCHEMA.md AND the actual pscustomobject construction (3.0.0).
// Deeply-nested/variable arrays (ContextLines, HexDump, ProviderMetadata) are kept
// as serde_json::Value because their per-row shape is not part of the stable contract.
// All names are plain PascalCase words (FileSha256, not FileSHA256), so rename_all
// covers them — no explicit renames needed here.
// ---------------------------------------------------------------------------

/// `OffsetInspect.Result` (Invoke-OffsetInspect; also nested as ThreatScanResult.Inspection)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct OffsetResult {
    pub success: bool,
    pub file: Option<String>,
    pub offset_input: Option<String>,
    pub offset_decimal: Option<i64>,
    pub offset_hex: Option<String>,
    pub file_size: Option<i64>,
    pub encoding_requested: Option<String>,
    pub encoding_detected: Option<String>,
    pub line_number: Option<i64>,
    pub line_text: Option<String>,
    pub line_text_truncated: bool,
    pub character_position: Option<i32>,
    pub preview_character_position: Option<i32>,
    pub byte_position_in_line: Option<i64>,
    #[serde(default)]
    pub context_lines: Vec<Value>,
    pub target_byte_hex: Option<String>,
    pub target_byte_decimal: Option<i32>,
    pub compare_file: Option<String>,
    pub compare_byte_hex: Option<String>,
    pub compare_byte_decimal: Option<i32>,
    pub bytes_differ: Option<bool>,
    pub window_start_offset: Option<i64>,
    pub window_end_offset: Option<i64>,
    #[serde(default)]
    pub hex_dump: Vec<Value>,
    pub duration_ms: f64,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

/// `OffsetInspect.ThreatScanResult` (Invoke-OffsetThreatScan — Windows-only)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ThreatScanResult {
    pub success: bool,
    pub file: Option<String>,
    pub file_size: Option<i64>,
    pub file_sha256: Option<String>,
    pub scan_timestamp_utc: Option<String>,
    pub engine: Option<String>,
    pub scan_mode: Option<String>,
    pub boundary_unit: Option<String>,
    pub search_model: Option<String>,
    pub encoding: Option<String>,
    pub initial_status: Option<String>,
    pub detection_prefix_length: Option<i64>,
    pub detection_boundary_offset: Option<i64>,
    pub detection_boundary_hex: Option<String>,
    pub detection_character_index: Option<i64>,
    pub detection_utf16_code_unit_index: Option<i64>,
    pub known_clean_prefix_length: Option<i64>,
    pub stable: bool,
    pub confidence: Option<String>,
    pub scan_count: i32,
    pub signature_name: Option<String>,
    pub provider_result: Option<Value>,   // Mixed (int or null)
    pub provider_h_result: Option<Value>, // Mixed (hex string or null)
    pub provider_metadata: Option<Value>, // dynamic object
    pub boundary_validation: Option<BoundaryValidation>,
    pub provider_output: Option<String>,
    #[serde(default)]
    pub probe_log: Vec<ProbeLogEntry>,
    pub inspection: Option<OffsetResult>,
    pub duration_ms: f64,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BoundaryValidation {
    #[serde(default)]
    pub full_content_statuses: Vec<String>,
    #[serde(default)]
    pub known_clean_statuses: Vec<String>,
    #[serde(default)]
    pub known_detected_statuses: Vec<String>,
}

/// One `ProbeLog` record (a distinct provider invocation / cache miss).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ProbeLogEntry {
    pub sequence: i64,
    pub prefix_length: i64,
    pub status: String,
    pub provider_result: Option<Value>,
    pub signature_name: Option<String>,
    pub cacheable: bool,
    pub elapsed_ms: f64,
    pub timestamp_utc: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_serializes_with_offsetinspect_field_names() {
        let ioc = Ioc {
            file: "x".into(),
            file_size: 10,
            md5: "m".into(),
            sha1: "s1".into(),
            sha256: "s2".into(),
            overall_entropy: 1.0,
            high_entropy_windows: 0,
            printable_string_count: 0,
            is_pe: false,
            machine: None,
            imp_hash: None,
            imported_dll_count: None,
            has_overlay: None,
            overlay_size: None,
        };
        let json = serde_json::to_string(&ioc).unwrap();
        for key in [
            "\"MD5\":",
            "\"SHA1\":",
            "\"SHA256\":",
            "\"IsPE\":",
            "\"OverallEntropy\":",
            "\"HighEntropyWindows\":",
            "\"PrintableStringCount\":",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
        // The wrong PascalCase casings must NOT appear.
        assert!(!json.contains("\"Md5\":"));
        assert!(!json.contains("\"IsPe\":"));
    }

    #[test]
    fn peinfo_uses_the_ispe32plus_rename() {
        let pe = PeInfo {
            file: "x".into(),
            file_size: 0,
            machine: "x64 (AMD64)".into(),
            is_pe32_plus: true,
            entry_point_rva: 0,
            entry_point_hex: "0x0".into(),
            image_base: 0,
            section_count: 0,
            sections: vec![],
            imported_dll_count: 0,
            imports: vec![],
            imp_hash: None,
            resource_size: 0,
            has_overlay: false,
            overlay_offset: None,
            overlay_size: 0,
            mapped_offset: None,
            mapped_section: None,
            warnings: vec![],
        };
        let json = serde_json::to_string(&pe).unwrap();
        assert!(json.contains("\"IsPE32Plus\":"));
        assert!(!json.contains("\"IsPe32Plus\":"));
    }
}
