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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_runs_with_offsets_and_encoding() {
        let data = b"\x00\x00hello\x00hi world\x00";
        let hits = extract_ascii_strings(data, 4);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].value, "hello");
        assert_eq!(hits[0].offset, 2);
        assert_eq!(hits[0].encoding, "Ascii");
        assert_eq!(hits[1].value, "hi world");
        assert_eq!(hits[1].offset, 8);
    }

    #[test]
    fn honours_the_minimum_length() {
        let data = b"ab\x00abcd";
        let hits = extract_ascii_strings(data, 4);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "abcd");
        assert_eq!(hits[0].offset, 3);
    }

    #[test]
    fn extracts_utf16le_runs() {
        // "OK" in UTF-16LE = 4F 00 4B 00
        let data = [0x4F, 0x00, 0x4B, 0x00];
        let hits = extract_utf16le_strings(&data, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "OK");
        assert_eq!(hits[0].encoding, "Unicode");
        assert_eq!(hits[0].length, 2);
    }
}
