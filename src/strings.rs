//! Printable string extraction — mirrors `Get-OffsetString`.

use crate::schema::StringHit;

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Extract runs of printable ASCII bytes of at least `min_length`.
pub fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<StringHit> {
    let mut hits = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            push_ascii_hit(data, start, i, min_length, &mut hits);
        }
    }
    if let Some(start) = run_start {
        push_ascii_hit(data, start, data.len(), min_length, &mut hits);
    }
    hits
}

fn push_ascii_hit(
    data: &[u8],
    start: usize,
    end: usize,
    min_length: usize,
    hits: &mut Vec<StringHit>,
) {
    let len = end - start;
    if len >= min_length {
        if let Ok(value) = std::str::from_utf8(&data[start..end]) {
            hits.push(StringHit {
                offset: start as u64,
                offset_hex: format!("0x{:X}", start),
                encoding: "Ascii".to_string(),
                length: len as u32,
                value: value.to_string(),
            });
        }
    }
}

/// Extract runs of printable UTF-16LE code units of at least `min_length` characters.
pub fn extract_utf16le_strings(data: &[u8], min_length: usize) -> Vec<StringHit> {
    let mut hits = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut chars: Vec<u16> = Vec::new();
    let mut i = 0usize;

    while i + 1 < data.len() {
        let unit = u16::from_le_bytes([data[i], data[i + 1]]);
        let printable = (0x20..=0x7e).contains(&unit);
        if printable {
            if run_start.is_none() {
                run_start = Some(i);
                chars.clear();
            }
            chars.push(unit);
        } else if let Some(start) = run_start.take() {
            push_utf16_hit(start, &chars, min_length, &mut hits);
            chars.clear();
        }
        i += 2;
    }
    if let Some(start) = run_start {
        push_utf16_hit(start, &chars, min_length, &mut hits);
    }
    hits
}

fn push_utf16_hit(start: usize, chars: &[u16], min_length: usize, hits: &mut Vec<StringHit>) {
    if chars.len() >= min_length {
        if let Ok(value) = String::from_utf16(chars) {
            hits.push(StringHit {
                offset: start as u64,
                offset_hex: format!("0x{:X}", start),
                encoding: "Unicode".to_string(),
                length: chars.len() as u32,
                value,
            });
        }
    }
}
