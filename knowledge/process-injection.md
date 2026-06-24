# Process Injection

Search tags: process-injection injection windows OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread NtCreateThreadEx QueueUserAPC SetWindowsHookEx shellcode

RAG summary: Process injection evidence indicates the binary may manipulate another process, write code or data into it, and execute that content. A single API is capability evidence; a chain of APIs is much stronger.

## Common indicators

- Target access: `OpenProcess`, `NtOpenProcess`, process enumeration APIs.
- Remote memory: `VirtualAllocEx`, `NtAllocateVirtualMemory`, `WriteProcessMemory`.
- Execution transfer: `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetWindowsHookEx`.
- Permission changes: `VirtualProtectEx`, `NtProtectVirtualMemory`.
- Strings: target process names, DLL paths, shellcode markers, `rundll32`, `svchost`, `explorer.exe`.

## Risk interpretation

Process injection is high-risk because it can hide execution inside another process, bypass controls, or interact with privileged targets. It is also used by debuggers, profilers, accessibility tools, EDR, and automation frameworks.

## Stronger evidence combinations

- `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`: classic injection chain.
- dynamic import resolution + injection APIs: possible evasive loader.
- anti-debugging + injection APIs: possible malware or protected injector.
- network download + injection APIs: possible staged payload execution.

## False positive notes

Do not call it injection solely from `OpenProcess`. Require at least remote memory write or remote execution transfer for stronger wording.

## Analyst checklist

- Identify whether APIs target the current process or another process.
- Look for requested access rights and process names.
- Check whether remote memory receives decoded, downloaded, or embedded payload data.
- Preserve exact API chain and disassembly snippets.
