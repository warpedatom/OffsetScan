//! Optional YARA rule matching — mirrors `Invoke-OffsetYaraScan`
//! (OffsetInspect.YaraMatch). Compiled in only with the `yara-scan` feature,
//! which vendors libyara; the default build omits it entirely.
//!
//! Parity notes vs OffsetInspect's `Invoke-OffsetYaraScan`:
//!  - One record per matched string with fields `File`, `Rule`, `StringId` (e.g. `$a`),
//!    `Offset` (decimal), `OffsetHex` (lowercase `0x..`), `Data` (matched bytes).
//!  - `Data` is decoded lossily from the matched bytes; for non-printable/binary matches
//!    the textual form can differ from the YARA CLI's rendering that OffsetInspect parses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraHit {
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "Rule")]
    pub rule: String,
    #[serde(rename = "StringId")]
    pub string_id: String,
    #[serde(rename = "Offset")]
    pub offset: u64,
    #[serde(rename = "OffsetHex")]
    pub offset_hex: String,
    #[serde(rename = "Data")]
    pub data: String,
}

/// Compile one or more rule files and scan a single file, returning one `YaraHit` per
/// matched string. `timeout_secs` bounds the scan.
#[cfg(feature = "yara-scan")]
pub fn scan_with_rules(
    file_path: &str,
    rule_paths: &[String],
    timeout_secs: i32,
) -> Result<Vec<YaraHit>, String> {
    use yara::Compiler;

    let mut compiler = Compiler::new().map_err(|e| format!("YARA compiler init failed: {e}"))?;
    for rule_path in rule_paths {
        compiler = compiler
            .add_rules_file(rule_path)
            .map_err(|e| format!("failed to load rules '{rule_path}': {e}"))?;
    }
    let rules = compiler
        .compile_rules()
        .map_err(|e| format!("rule compilation failed: {e}"))?;
    let matches = rules
        .scan_file(file_path, timeout_secs)
        .map_err(|e| format!("scan failed: {e}"))?;

    let mut hits = Vec::new();
    for rule_match in matches {
        for string_match in rule_match.strings {
            // OffsetInspect reports the id with a leading '$' (e.g. "$a").
            let string_id = if string_match.identifier.starts_with('$') {
                string_match.identifier.to_string()
            } else {
                format!("${}", string_match.identifier)
            };
            for m in string_match.matches {
                hits.push(YaraHit {
                    file: file_path.to_string(),
                    rule: rule_match.identifier.to_string(),
                    string_id: string_id.clone(),
                    offset: m.offset as u64,
                    offset_hex: format!("0x{:x}", m.offset),
                    data: String::from_utf8_lossy(&m.data).to_string(),
                });
            }
        }
    }
    Ok(hits)
}

/// Stub for builds without the `yara-scan` feature: returns a clear rebuild instruction so
/// the `yara` subcommand exists but explains what's missing.
#[cfg(not(feature = "yara-scan"))]
pub fn scan_with_rules(
    _file_path: &str,
    _rule_paths: &[String],
    _timeout_secs: i32,
) -> Result<Vec<YaraHit>, String> {
    Err(
        "offsetscan was built without the `yara-scan` feature; rebuild with \
         `cargo build --release --features yara-scan` (needs a C toolchain and libclang)."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_hit_serializes_with_offsetinspect_field_names() {
        // Locks the interchange field names against Invoke-OffsetYaraScan's records, even in
        // the default build where the scanner itself isn't compiled.
        let hit = YaraHit {
            file: "f".to_string(),
            rule: "R".to_string(),
            string_id: "$a".to_string(),
            offset: 100,
            offset_hex: "0x64".to_string(),
            data: "x".to_string(),
        };
        let json = serde_json::to_string(&hit).unwrap();
        for field in ["File", "Rule", "StringId", "Offset", "OffsetHex", "Data"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing field {field}"
            );
        }
    }
}
