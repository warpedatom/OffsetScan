# Changelog

All notable changes to OffsetScan are documented in this file.
The project follows semantic versioning.

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
