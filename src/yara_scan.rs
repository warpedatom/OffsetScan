//! Optional YARA rule matching — mirrors `Invoke-OffsetYaraScan`.
//! Only compiled in when the `yara-scan` feature is enabled, matching
//! OffsetInspect's stance that YARA is the one optional external dependency.

#[cfg(feature = "yara-scan")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "yara-scan")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraHit {
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "RuleName")]
    pub rule_name: String,
    #[serde(rename = "Offset")]
    pub offset: u64,
    #[serde(rename = "Identifier")]
    pub identifier: String,
}

#[cfg(feature = "yara-scan")]
#[allow(dead_code)] // wired to a CLI subcommand only once YARA integration lands
pub fn scan_with_rules(
    file_path: &str,
    rule_path: &str,
) -> Result<Vec<YaraHit>, String> {
    use yara::Compiler;

    let compiler = Compiler::new()
        .map_err(|e| format!("YARA compiler init failed: {e}"))?
        .add_rules_file(rule_path)
        .map_err(|e| format!("failed to load rules '{rule_path}': {e}"))?;
    let rules = compiler
        .compile_rules()
        .map_err(|e| format!("rule compilation failed: {e}"))?;

    let results = rules
        .scan_file(file_path, 30)
        .map_err(|e| format!("scan failed: {e}"))?;

    let mut hits = Vec::new();
    for rule_match in results {
        for string_match in rule_match.strings {
            for m in string_match.matches {
                hits.push(YaraHit {
                    file: file_path.to_string(),
                    rule_name: rule_match.identifier.to_string(),
                    offset: m.offset as u64,
                    identifier: string_match.identifier.to_string(),
                });
            }
        }
    }
    Ok(hits)
}

#[cfg(not(feature = "yara-scan"))]
#[allow(dead_code)] // wired to a CLI subcommand only once YARA integration lands
pub fn scan_with_rules(_file_path: &str, _rule_path: &str) -> Result<Vec<()>, String> {
    Err("offsetscan was built without the `yara-scan` feature; rebuild with \
         `cargo build --release --features yara-scan` and ensure the YARA \
         engine is installed."
        .to_string())
}
