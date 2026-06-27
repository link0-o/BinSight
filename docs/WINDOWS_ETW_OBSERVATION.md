# Windows ETW Expert Observation

## Purpose

`observe windows-etw` is an explicit expert mode for Windows samples where static analysis is not enough, such as packed or strongly obfuscated PE files. It runs the target on the local Windows host and records bounded runtime evidence that can be merged back into a normal BinSight scan.

This mode is not a sandbox. It does not isolate, intercept, or block malicious behavior.

## Command

```powershell
.\bin\binsight.exe observe windows-etw .\sample.exe `
  --out dynamic.json `
  --i-understand-risk `
  --timeout 90 `
  --max-events 5000 `
  --max-json-bytes 10485760 `
  --network observe

.\bin\binsight.exe scan .\sample.exe --dynamic-report dynamic.json
```

## Evidence Collected

The first release records a bounded summary:

- process start and exit for the target process
- child process discovery
- TCP connection snapshots owned by the observed process tree
- nearby file create, modify, and delete summaries in the target directory
- exit code and timeout status
- warnings describing limits and risk boundaries

The report marks this evidence as `platform=windows` and `mode=windows_etw`.

## Storage Policy

BinSight does not save raw `.etl` traces by default. It writes only `dynamic.json`.

Default limits:

- `--max-events 5000`
- `--max-json-bytes 10485760`
- `--timeout 90`

When a limit is reached, BinSight stops appending detailed events and writes a warning. This keeps release packages and per-run output small. The expected package size increase is roughly 1-5 MB compressed and 3-15 MB extracted.

## Industrial Component Decision

Windows ETW is the operating system's standard tracing interface. For this first release, BinSight uses Windows SDK APIs and system observation APIs directly because they are the industrial standard and avoid additional runtime payload. A wrapper such as Microsoft `krabsetw` remains a future option if the ETW provider coverage expands.

This is not a custom binary parser or a required CLI-tool dependency. No Sysmon, Procmon, VM image, or Windows SDK tool is bundled in the release package.

## Safety Boundary

Use this mode only when all of the following are true:

- you understand the file will execute on the local host
- the host is a lab machine or otherwise disposable
- you accept that BinSight cannot prevent persistence, file modification, network access, or other side effects

For high-risk malware, use a dedicated VM or professional sandbox.

