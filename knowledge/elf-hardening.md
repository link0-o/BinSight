# ELF Hardening

Search tags: elf hardening PIE RELRO NX stack-canary __stack_chk_fail stripped executable security weakness

RAG summary: ELF hardening describes exploit-resistance features, not malware behavior. Missing PIE, RELRO, stack canaries, or NX can indicate security weakness, but it should not be treated as malicious intent by itself.

## Common indicators

- PIE: position independent executable support.
- RELRO: read-only relocation protection; full RELRO is stronger than partial RELRO.
- NX: non-executable stack or data memory.
- Stack canary: imports such as `__stack_chk_fail`.
- Symbol stripping: fewer names for analyst context, but not a direct risk by itself.

## Risk interpretation

Hardening findings are most useful for vulnerability triage and exploitability assessment. They should be reported separately from behavior-based malware indicators. Severity rises when missing hardening appears in privileged, network-facing, or setuid-style binaries.

## Stronger evidence combinations

- missing hardening + network service behavior: larger exploit surface.
- writable executable sections + missing NX: possible code execution weakness.
- not stripped + sensitive symbols: may expose implementation details.

## False positive notes

Older toolchains, embedded systems, test binaries, and performance-sensitive builds may lack some hardening. Avoid using missing hardening as a malware claim.

## Analyst checklist

- Distinguish weakness from malicious behavior.
- Note whether the binary is privileged or network-facing.
- Preserve exact hardening evidence and tool output.
