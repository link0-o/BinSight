---
id: pe-imports
rules: []
apis: [CreateProcessA, CreateProcessW, ShellExecuteA, WinExec, OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtCreateThreadEx, VirtualAlloc, VirtualProtect, LoadLibraryA, LoadLibraryW, GetProcAddress, WinHttpOpen, InternetOpenA, URLDownloadToFileA, WSAStartup, RegSetValueExA]
strings: [schtasks, service, registry, dll, rundll32]
tags: [pe, imports, windows, dll, api]
platforms: [windows]
---

# PE Imports

Search tags: pe imports windows dll api process-injection command-execution network-capability persistence CreateProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread WinHttpOpen RegSetValueEx

RAG summary: PE imports reveal Windows API capabilities. They are strong triage signals but not behavior proof. Risk comes from suspicious combinations such as process injection APIs, persistence APIs, command execution APIs, networking APIs, and dynamic import resolution.

## High-value import groups

- Process execution: `CreateProcessA`, `CreateProcessW`, `ShellExecuteA`, `WinExec`.
- Process injection: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`.
- Memory permissions: `VirtualAlloc`, `VirtualProtect`, `NtProtectVirtualMemory`.
- Dynamic loading: `LoadLibraryA`, `LoadLibraryW`, `GetProcAddress`.
- Networking: `WinHttpOpen`, `InternetOpenA`, `InternetConnectA`, `URLDownloadToFileA`, `WSAStartup`.
- Persistence: `RegCreateKeyExA`, `RegSetValueExA`, `CreateServiceA`, `StartServiceA`, `schtasks` strings.

## Risk interpretation

One import usually indicates capability. A coherent chain is more meaningful: download content, allocate memory, write into another process, and start a remote thread. The report should identify the chain rather than over-weighting a single API.

## Stronger evidence combinations

- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`: classic remote injection chain.
- `URLDownloadToFileA` + `CreateProcessA`: downloader-executor behavior.
- `RegSetValueExA` + startup paths: possible persistence.

## False positive notes

Admin tools, debuggers, installers, EDR agents, and automation software can import high-risk APIs legitimately. Explain capability and ask for call-site review when intent is unclear.

## Analyst checklist

- Group imports into behavior chains.
- Preserve DLL names and imported function names.
- Look for matching strings such as service names, registry paths, URLs, or process names.
