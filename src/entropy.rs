//! Per-window Shannon entropy — mirrors `Get-OffsetEntropy` (OffsetInspect.EntropyResult).
//!
//! Parity notes vs OffsetInspect:
//!  - Windows are CONTIGUOUS / non-overlapping (start += length), not a sliding step.
//!  - `EndOffset` is the INCLUSIVE last byte (start + length - 1).
//!  - Entropy values are rounded to 6 decimal places (OffsetInspect uses [Math]::Round(..,6)).
//!  - `OverallEntropy` is the entropy of the whole file's byte distribution.

use crate::schema::{EntropyResult, EntropyWindow};

fn round6(x: f64) -> f64 {
    let r = (x * 1_000_000.0).round() / 1_000_000.0;
    // Normalize IEEE negative zero to positive zero. Shannon entropy of a single-value
    // buffer computes -1 * log2(1) = -0.0, which serializes to JSON as "-0.0" and breaks
    // exact parity with Get-OffsetEntropy (which emits 0) on all-identical-byte files —
    // all-zero padding, sparse regions. `-0.0 == 0.0` is true, so this catches it.
    if r == 0.0 {
        0.0
    } else {
        r
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_a_single_repeated_byte_is_zero() {
        assert_eq!(shannon_entropy(&[0xAA; 64]), 0.0);
    }

    #[test]
    fn zero_entropy_serializes_as_positive_zero() {
        // Regression: -1 * log2(1) = -0.0 propagated to the output, so a zero-entropy file
        // reported "-0.0" and diverged from Get-OffsetEntropy's 0. assert_eq! can't catch it
        // (-0.0 == 0.0), so assert the sign bit explicitly, on both overall and per-window.
        assert!(round6(shannon_entropy(&[0x00; 256])).is_sign_positive());
        let r = build_entropy_result(&[0u8; 512], "x", 256, 7.0);
        assert!(
            r.overall_entropy.is_sign_positive(),
            "overall entropy must be +0.0, got {:?}",
            r.overall_entropy
        );
        assert!(
            r.windows.iter().all(|w| w.entropy.is_sign_positive()),
            "every window entropy must be +0.0"
        );
    }

    #[test]
    fn entropy_of_a_balanced_two_value_buffer_is_one_bit() {
        let data: Vec<u8> = (0..64u8).map(|i| i % 2).collect();
        assert!((shannon_entropy(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_a_uniform_distribution_is_eight_bits() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn windows_are_contiguous_with_inclusive_end_offsets() {
        let data = vec![0u8; 300];
        let r = build_entropy_result(&data, "x", 256, 7.0);
        assert_eq!(r.window_count, 2);
        assert_eq!(r.windows[0].start_offset, 0);
        assert_eq!(r.windows[0].end_offset, 255); // inclusive last byte
        assert_eq!(r.windows[1].start_offset, 256);
        assert_eq!(r.windows[1].end_offset, 299);
        assert_eq!(r.windows[1].length, 44);
    }

    #[test]
    fn high_entropy_windows_are_flagged_at_the_threshold() {
        let data: Vec<u8> = (0..=255u8).collect(); // one 256-byte uniform window = 8.0 bits
        let r = build_entropy_result(&data, "x", 256, 7.0);
        assert_eq!(r.high_window_count, 1);
        assert!(r.windows[0].is_high);
    }
}
