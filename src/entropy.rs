//! Per-window Shannon entropy — mirrors `Get-OffsetEntropy` (OffsetInspect.EntropyResult).
//!
//! Parity notes vs OffsetInspect:
//!  - Windows are CONTIGUOUS / non-overlapping (start += length), not a sliding step.
//!  - `EndOffset` is the INCLUSIVE last byte (start + length - 1).
//!  - Entropy values are rounded to 6 decimal places (OffsetInspect uses [Math]::Round(..,6)).
//!  - `OverallEntropy` is the entropy of the whole file's byte distribution.

use crate::schema::{EntropyResult, EntropyWindow};

fn round6(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

/// Shannon entropy (bits/byte) of a byte slice — raw, unrounded.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Build the full `OffsetInspect.EntropyResult` for a file.
pub fn build_entropy_result(
    data: &[u8],
    file: &str,
    window_size: usize,
    high_threshold: f64,
) -> EntropyResult {
    let mut windows = Vec::new();
    if window_size > 0 && !data.is_empty() {
        let mut index = 0u32;
        let mut start = 0usize;
        while start < data.len() {
            let end = (start + window_size).min(data.len()); // exclusive slice bound
            let length = end - start;
            let entropy = round6(shannon_entropy(&data[start..end]));
            windows.push(EntropyWindow {
                index,
                start_offset: start as u64,
                start_hex: format!("0x{:X}", start),
                end_offset: (start + length - 1) as u64, // inclusive
                length: length as u32,
                entropy,
                is_high: entropy >= high_threshold,
            });
            index += 1;
            start += length;
        }
    }

    let high_window_count = windows.iter().filter(|w| w.is_high).count() as u32;
    EntropyResult {
        file: file.to_string(),
        file_size: data.len() as u64,
        window_size: window_size as u32,
        window_count: windows.len() as u32,
        overall_entropy: round6(shannon_entropy(data)),
        high_entropy_threshold: high_threshold,
        high_window_count,
        windows,
    }
}
