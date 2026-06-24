---
id: crypto-packing-obfuscation
rules: [writable-executable-section]
apis: [VirtualAlloc, VirtualAllocEx, mmap, mprotect, VirtualProtect, NtProtectVirtualMemory, LoadLibraryA, LoadLibraryW, GetProcAddress, dlopen, dlsym]
strings: [AES, RC4, ChaCha20, zlib, inflate, UPX, base64]
tags: [memory, packing, obfuscation, crypto, high-entropy]
platforms: [windows, linux]
---

# Crypto, Packing, and Obfuscation

Search tags: writable-executable-section memory packing obfuscation crypto high-entropy VirtualAlloc VirtualProtect mmap mprotect LoadLibrary GetProcAddress dlopen dlsym UPX

RAG summary: Crypto, packing, and obfuscation evidence can indicate legitimate protection or malicious concealment. Treat it as higher risk when high-entropy or writable-executable sections appear with anti-debugging, runtime allocation, import resolution, network behavior, or process injection.

## Common indicators

- Section signs: high entropy, unusual section names, very small import table, packed-looking overlay, writable and executable flags.
- Memory APIs: `VirtualAlloc`, `VirtualAllocEx`, `mmap`, `mprotect`, `VirtualProtect`, `NtProtectVirtualMemory`.
- Dynamic loading: `LoadLibraryA`, `LoadLibraryW`, `GetProcAddress`, `dlopen`, `dlsym`.
- Crypto/compression strings: `AES`, `RC4`, `ChaCha20`, `zlib`, `inflate`, `UPX`, `base64`.
- Control-flow signs: indirect jumps, decode loops, self-modifying code, import reconstruction.

## Risk interpretation

Packing and obfuscation are dual-use. They are common in commercial protectors and malware loaders. The report should describe the observed concealment technique and explain which additional behaviors make it risky.

## Stronger evidence combinations

- writable executable section + anti-debugging: possible protected or unpacking payload.
- dynamic import resolution + process injection APIs: possible loader behavior.
- crypto strings + network URLs: possible encrypted command-and-control or protected payload download.

## False positive notes

UPX, DRM, anti-cheat, and commercial licensing systems can look suspicious. Avoid claiming packed malware unless there is supporting behavioral evidence.

## Analyst checklist

- Check whether imports are sparse compared with observed behavior.
- Look for runtime permission changes from writable to executable.
- Look for decompression or decryption loops before jumps into allocated memory.
- Record exact section names, flags, and suspicious APIs.
