# Changelog

All notable changes to OffsetScan are documented in this file.
The project follows semantic versioning.

## [0.1.4] - 2026-07-21

### Fixed

- **Structurally-damaged PEs are no longer rejected outright.** goblin does strict
  full-structure validation, so a truncated or carved sample — headers intact but section
  data cut off, common with partial downloads and file-carving — was reported as
  `IsPE: false` with every PE field null, losing all triage value. `parse_pe` now falls
  back to a lenient header-salvage parse (mirroring OffsetInspect's `ConvertTo-OIPEImage`)
  when goblin rejects a file, recovering machine, sections, entry point, overlay, and any
  reachable imports/imphash. Valid PEs are unaffected — they always take the goblin path,
  verified unchanged across a 150-file corpus vs pefile. Across a 34-file malformed corpus
  (truncations, bit-flips, corrupted directories, bogus section counts, pure garbage),
  `IsPE` now agrees with OffsetInspect on all 34 (was 22/34), and neither engine crashes or
  hangs on any input. Genuinely unparseable inputs (no MZ/PE signature, or a section count
  that cannot fit) are still rejected, matching OffsetInspect.

### Added

- Lenient-parse unit tests: header-only PE salvage, and rejection of non-PE buffers and
  unfittable section counts.

## [0.1.3] - 2026-07-20

### Fixed

- **imphash now resolves ordinal imports from `ws2_32`/`wsock32`/`oleaut32` to their real
  function names, matching pefile and VirusTotal.** Previously these rendered as `ord<N>`,
  so any binary importing those libraries by ordinal — a common malware networking
  pattern — produced an imphash that did not match the value on VirusTotal, defeating the
  imphash's purpose of correlating a sample against threat intel. Verified against pefile
  across a 150-file corpus (44 exercising the special-ordinal path): 0 mismatches, and 15
  binaries that previously diverged now agree. Other ordinal imports still render `ord<N>`,
  exactly as pefile does.

### Added

- `src/ordinals.rs`: pefile's `ws2_32`/`wsock32`/`oleaut32` ordinal->name tables (696
  entries), generated verbatim from pefile 2024.8.26, with unit tests. Kept in lockstep
  with OffsetInspect's `Core.PE.Ordinals.ps1`.

## [0.1.2] - 2026-07-20

### Fixed

- **`OverallEntropy` (and per-window entropy) reported `-0.0` for a zero-entropy file.**
  Shannon entropy of an all-identical-byte buffer computes `-1 * log2(1) = -0.0` (IEEE
  negative zero), which serialized to JSON as `"-0.0"` and diverged from
  `Get-OffsetEntropy`, which emits `0`. Negative zero is now normalized to positive zero
  at the rounding step, so both engines agree exactly on all-identical-byte inputs
  (all-zero padding, sparse regions). Verified against a 256 KiB zero file: both now
  report `0`.

### Added

- A regression test asserting zero entropy carries a positive sign bit on both the overall
  value and every window. The prior test used `assert_eq!`, which cannot distinguish
  `-0.0` from `0.0`, so the sign defect passed unnoticed.

## [0.1.1] - 2026-07-20

### Fixed

- **UTF-16LE string extraction missed every unaligned run.** The scanner stepped two
  bytes unconditionally from offset 0, so it only ever inspected even-aligned code
  units and silently skipped any UTF-16LE string beginning at an odd offset. It now
  resynchronizes one byte at a time after a non-match, mirroring `Get-OIByteString`.
  This under-reported `PrintableStringCount` in the `ioc` panel and omitted hits from
  `strings` — on `user32.dll`, 36 of 366 UTF-16LE strings were missing. Verified after
  the fix: `offsetscan strings` and `Get-OffsetString` return set-identical results
  (offset, encoding, and value) for `ntdll.dll` — 32,506 strings, zero differences on
  either side.
- The UTF-16LE printability test now explicitly requires a zero high byte rather than
  range-checking the assembled `u16`, matching the reference implementation.

### Added

- Regression tests for odd-offset UTF-16LE runs, mixed aligned/unaligned runs in one
  pass, and the zero-high-byte requirement. The previous UTF-16 test used a string at
  offset 0, so it could not catch the alignment bug.

## [0.1.0] - 2026-07-20

First tagged release. Prebuilt Linux/Windows binaries are attached to the GitHub
release; otherwise `cargo build --release`.

### Engine

- `pe`, `entropy`, `strings`, and `ioc` subcommands; rayon parallel corpus
  scanning (file / directory `--recurse` / glob); JSON output schema-compatible
  with OffsetInspect's `Get-OffsetPEInfo` / `Get-OffsetEntropy` /
  `Get-OffsetString` / `Get-OffsetIOC`, verified field-for-field with the imphash
  cross-checked at runtime.

### Added

- `--offset <dec|0xhex>` on the `pe` subcommand: maps a byte offset to its
  containing PE section (populates `MappedOffset` / `MappedSection`).
- `--ndjson` global flag: newline-delimited JSON, streamed as each file finishes
  so peak memory stays flat over very large corpora. Default output remains a
  pretty-printed JSON array for OffsetInspect drop-in compatibility.
- `--csv` flag (`ioc` subcommand only): flat header + one-row-per-file table
  whose columns match the JSON field names, for spreadsheet / SIEM import.
- crates.io publish metadata (`keywords`, `categories`, `readme`) so the engine
  can be installed with `cargo install offsetscan`.
- Unit-test suite: Shannon entropy known-vectors, contiguous/inclusive window
  offsets, ASCII/UTF-16LE string extraction, PE helpers and non-PE rejection,
  and the parity-critical schema field-name renames
  (`MD5`/`SHA1`/`SHA256`/`IsPE`/`IsPE32Plus`).
- GitHub Actions CI (`rustfmt`, `clippy -D warnings`, build + test on
  `ubuntu-latest` and `windows-latest`) and a tag-triggered release workflow
  that publishes prebuilt binaries.
- MIT `LICENSE`, README badges, and `SECURITY.md`.

### Notes

- The `yara-scan` feature is experimental: it compiles behind the `yara` crate
  but is not built in CI and is untested against real rules.
