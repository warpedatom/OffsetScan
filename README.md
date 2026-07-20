# OffsetScan

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

**Before wiring this into the real pipeline:** diff `src/schema.rs` against
the authoritative `docs/OUTPUT-SCHEMA.md` in `warpedatom/OffsetInspect` and
correct any field-name/casing mismatches. The struct definitions here are a
best-effort mirror based on the public README descriptions, not a verified
1:1 copy of the real schema doc.

## Build

```
cargo build --release
# With optional YARA support (requires the YARA engine installed):
cargo build --release --features yara-scan
```

## Usage

```
offsetscan pe ./sample.exe
offsetscan entropy ./payload.bin --window 256 --high-threshold 7.2
offsetscan strings ./sample.bin --min-length 6
offsetscan ioc ./sample.exe

# Corpus mode (any subcommand):
offsetscan ioc ./samples --recurse
```

All commands emit pretty-printed JSON arrays to stdout, matching
OffsetInspect's JSON-mode convention (always an array, even for one result).

## Consuming from PowerShell

```powershell
$offsetscanResults = offsetscan ioc ./samples --recurse | ConvertFrom-Json
$offsetscanResults | Export-OffsetThreatReport -Path ./engagement.html -IncludeIoc
```

Because the JSON shape matches `Get-OffsetIOC`'s output, `Export-OffsetThreatReport`
and any other consumer of that shape should accept OffsetScan's output as a
drop-in, faster-at-scale alternative — pending the schema verification note
above.

## What's intentionally NOT here

- AMSI / Microsoft Defender scanning — stays in OffsetInspect (Windows-only,
  needs the actual providers).
- Detection-boundary bisection search — that's a stateful, provider-driven
  workflow (`Invoke-OffsetThreatScan`), not a stateless corpus pass.
- ClamAV integration — `clamscan` process-spawning has no real parallel-corpus
  benefit from a Rust rewrite; left in PowerShell.

## Status

Early scaffold. `resource_size` in `PeInfo` is not yet computed (needs a
resource-directory walk). YARA feature is wired to the `yara` crate's API
shape but untested against a real rule file. No test suite yet — `tests/`
and `benchmarks/` directories are placeholders mirroring OffsetInspect's
layout for parity.
