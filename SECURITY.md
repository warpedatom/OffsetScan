# Security Policy

OffsetScan is a read-only, cross-platform static-analysis tool: it parses files
(PE headers, raw bytes) and emits JSON. It does not execute samples, modify the
files it reads, or interact with endpoint protection.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via a GitHub security advisory
(**Security → Advisories → Report a vulnerability**) at
https://github.com/warpedatom/OffsetScan. For non-sensitive reports you may open
a regular issue. **Do not attach live malware samples to public issues or PRs.**

## Supported versions

The latest `main` is the supported version. OffsetScan is intended for
authorized defensive research, malware triage, and reverse engineering.
