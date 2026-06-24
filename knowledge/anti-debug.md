# Anti Debugging

Search tags: anti-debug anti-debugging debugger sandbox evasion IsDebuggerPresent CheckRemoteDebuggerPresent ptrace BeingDebugged TracerPid

RAG summary: Anti-debugging evidence indicates the binary may detect debuggers, sandboxes, analysts, or instrumentation. Treat it as suspicious when combined with packing, network behavior, command execution, persistence, or process injection. Anti-debugging alone is capability evidence, not proof of malicious intent.

## Common indicators

- Windows APIs: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugStringA`, `OutputDebugStringW`.
- Linux APIs and patterns: `ptrace`, `/proc/self/status`, `TracerPid`, timing checks, signal abuse.
- Strings: `debugger`, `anti-debug`, `BeingDebugged`, `NtGlobalFlag`, `sandbox`, `vmware`, `virtualbox`.
- Behavioral hints: long sleeps, timing deltas, exception tricks, checksum checks around code sections.

## Risk interpretation

Anti-debugging is common in malware, packers, commercial protectors, games, DRM, and anti-cheat software. Severity should rise when anti-debugging appears with executable writable memory, suspicious network destinations, shell execution, credential strings, or process manipulation APIs.

## Stronger evidence combinations

- `anti-debug` + `writable-executable-section`: possible packed or self-modifying code.
- `anti-debug` + `network-capability`: possible evasion before command-and-control communication.
- `anti-debug` + `process-injection`: possible malware loader or injector behavior.

## False positive notes

Do not claim malware solely from debugger checks. Commercial software may use these checks for licensing or tamper resistance. The report should say "anti-analysis capability observed" unless there is supporting behavior.

## Analyst checklist

- Identify whether checks happen early near program startup.
- Look for fallback paths when a debugger or sandbox is detected.
- Compare with product context: DRM and anti-cheat have plausible benign reasons.
- Preserve exact APIs, strings, and disassembly snippets as evidence.
