# Changelog

All notable changes to OffsetScan are documented in this file.
The project follows semantic versioning.

## [Unreleased]

### Added

- `--offset <dec|0xhex>` on the `pe` subcommand: maps a byte offset to its
  containing PE section (populates `MappedOffset` / `MappedSection`).
- `--ndjson` global flag: newline-delimited JSON output, streamed as each file
  finishes so peak memory stays flat over very large corpora. The default output
  remains a pretty-printed JSON array for OffsetInspect drop-in compatibility.
- Unit-test suite: Shannon entropy known-vectors, contiguous/inclusive window
  offsets, ASCII/UTF-16LE string extraction, PE helpers and non-PE rejection,
  and the parity-critical schema field-name renames
  (`MD5`/`SHA1`/`SHA256`/`IsPE`/`IsPE32Plus`).
- GitHub Actions CI: `rustfmt`, `clippy -D warnings`, and build + test on
  `ubuntu-latest` and `windows-latest`.
- MIT `LICENSE`, CI/license README badges, and `SECURITY.md`.

### Changed

- README corrected: the schema is verified field-for-field against OffsetInspect
  (imphash cross-checked at runtime), not a best-effort mirror; `resource_size`
  is computed; the `yara-scan` feature is documented as experimental.

## [0.1.0]

- Initial engine: `pe`, `entropy`, `strings`, and `ioc` subcommands; rayon
  parallel corpus scanning (file / directory `--recurse` / glob); JSON output
  schema-compatible with OffsetInspect's `Get-OffsetPEInfo` / `Get-OffsetEntropy`
  / `Get-OffsetString` / `Get-OffsetIOC`.
