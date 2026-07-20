# OffsetScan

[![CI](https://github.com/warpedatom/OffsetScan/actions/workflows/ci.yml/badge.svg)](https://github.com/warpedatom/OffsetScan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A standalone, native, corpus-scale companion to [OffsetInspect](https://github.com/warpedatom/OffsetInspect).

OffsetInspect's static-triage helpers (`Get-OffsetPEInfo`, `Get-OffsetEntropy`,
`Get-OffsetString`, `Get-OffsetIOC`) are cross-platform PowerShell and work
great for single-file, interactive analysis. OffsetScan exists for the other
end of the workload: **thousands of files**, where PowerShell's per-file
overhead adds up and a parallel, no-GC native core pays for itself.

OffsetScan does not touch AMSI or Microsoft Defender — that stays exactly
where it belongs, as Windows-only functionality in OffsetInspect. OffsetScan
only does the read-only, cross-platform static-analysis layer: PE parsing,
entropy, string extraction, hashing, and (optionally) YARA matching.

## Design contract

Every OffsetScan output struct (`src/schema.rs`) mirrors the equivalent
OffsetInspect PowerShell object field-for-field, so the two tools are
interchangeable at the JSON layer:

| OffsetScan (Rust)              | OffsetInspect (PowerShell) equivalent   |
| ------------------------------- | ---------------------------------------- |
| `offsetscan pe`                 | `Get-OffsetPEInfo`                       |
| `offsetscan entropy`            | `Get-OffsetEntropy`                      |
| `offsetscan strings`            | `Get-OffsetString`                       |
| `offsetscan ioc`                | `Get-OffsetIOC`                          |
| `offsetscan yara` (feature-gated) | `Invoke-OffsetYaraScan`                |

The struct definitions have been verified field-for-field against the
authoritative `docs/OUTPUT-SCHEMA.md` and the real OffsetInspect 3.x objects,
and cross-checked at runtime: `offsetscan ioc` and `Get-OffsetIOC` produce
byte-identical panels for the same file — **including the imphash**. The
serialized field names (`MD5`/`SHA1`/`SHA256`/`IsPE`/`IsPE32Plus`) are locked
by unit tests so the interchange contract can't silently drift.

## Build

```
cargo build --release
# With optional YARA support (requires the YARA engine installed):
cargo build --release --features yara-scan
```

## Usage

```
offsetscan pe ./sample.exe
offsetscan pe ./sample.exe --offset 0x5F85   # map a byte offset to its PE section
offsetscan entropy ./payload.bin --window 256 --high-threshold 7.2
offsetscan strings ./sample.bin --min-length 6
offsetscan ioc ./sample.exe

# Corpus mode (any subcommand):
offsetscan ioc ./samples --recurse

# Streaming output for large corpora — one compact JSON object per line,
# emitted as each file finishes so peak memory stays flat:
offsetscan ioc ./samples --recurse --ndjson
```

By default all commands emit a pretty-printed JSON array to stdout, matching
OffsetInspect's JSON-mode convention (always an array, even for one result).
Add `--ndjson` for newline-delimited JSON — pipe-friendly and constant-memory
over hundreds of thousands of files.

## Consuming from PowerShell

OffsetInspect 3.1.0+ ingests OffsetScan's IOC JSON directly, so a corpus report
runs off the native engine instead of re-scanning each file in PowerShell:

```powershell
offsetscan ioc ./samples --recurse > ./ioc.json
$results | Export-OffsetThreatReport -Path ./engagement.md -IocJsonPath ./ioc.json
```

Because the JSON shape matches `Get-OffsetIOC` field-for-field, any consumer of
that shape accepts OffsetScan's output as a drop-in, faster-at-scale alternative.

## What's intentionally NOT here

- AMSI / Microsoft Defender scanning — stays in OffsetInspect (Windows-only,
  needs the actual providers).
- Detection-boundary bisection search — that's a stateful, provider-driven
  workflow (`Invoke-OffsetThreatScan`), not a stateless corpus pass.
- ClamAV integration — `clamscan` process-spawning has no real parallel-corpus
  benefit from a Rust rewrite; left in PowerShell.

## Status

Validated against OffsetInspect and covered by a unit-test suite (Shannon
entropy vectors, string offsets, PE helpers, and the parity-critical schema
field names) that runs in CI on Linux and Windows. `resource_size` is computed
from the PE resource data directory. The `yara-scan` feature is **experimental**
— it compiles behind the `yara` crate but is not built in CI and is untested
against real rules; enable it only if you have the YARA engine installed.
