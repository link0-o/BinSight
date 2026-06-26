---
id: command-execution
rules: [command-execution-capability, dangerous-command-exec]
apis: [system, popen, execl, execle, execlp, execv, execve, posix_spawn, WinExec, ShellExecuteA, ShellExecuteW, CreateProcessA, CreateProcessW]
strings: [shutdown, /bin/sh, /bin/bash, bash -c, cmd.exe, powershell, wscript, cscript, curl, wget, schtasks]
tags: [command-execution, process, shell]
platforms: [windows, linux]
---

# Command Execution

Search tags: dangerous-command-exec command-execution process shell system popen execve WinExec ShellExecute CreateProcess powershell cmd.exe bash

RAG summary: Command execution evidence means the binary can start processes or invoke shells. Risk is highest when command strings are dynamic, shell interpreters are present, or execution is combined with network input, persistence, archive extraction, or privilege-sensitive paths.

## Common indicators

- POSIX APIs: `system`, `popen`, `execl`, `execle`, `execlp`, `execv`, `execve`, `posix_spawn`.
- Windows APIs: `WinExec`, `ShellExecuteA`, `ShellExecuteW`, `CreateProcessA`, `CreateProcessW`.
- Shell strings: `/bin/sh`, `/bin/bash`, `bash -c`, `cmd.exe`, `powershell`, `wscript`, `cscript`.
- Suspicious command fragments: `curl`, `wget`, `chmod +x`, `schtasks`, `reg add`, `net user`, `base64 -d`.

## Risk interpretation

Command execution is not automatically malicious. Installers, launchers, build tools, and system utilities often spawn processes. Risk increases when the binary accepts external input, downloads content, builds command strings at runtime, or executes through a shell rather than directly invoking a known binary.

## Stronger evidence combinations

- `command-execution` + `network-capability`: possible downloader, updater, or command-and-control execution path.
- `command-execution` + credential strings: possible credential dumping or exfiltration helper.
- `command-execution` + persistence strings: possible installation of startup tasks or services.

## False positive notes

Reports should avoid saying "remote code execution" unless network-controlled command content is observed. Prefer "process launch capability" or "shell execution capability" when only imports or strings are present.

## Analyst checklist

- Determine whether command arguments are constant or built from input.
- Check whether the code invokes a shell interpreter.
- Look for download-before-execute sequences.
- Preserve the exact function, shell string, and nearby disassembly snippet.
