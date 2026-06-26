---
id: network-behavior
rules: [network-capability, suspicious-network-behavior]
apis: [socket, connect, send, recv, getaddrinfo, inet_addr, InternetOpenA, InternetOpenW, InternetConnectA, InternetConnectW, WinHttpOpen, URLDownloadToFileA, WSAStartup]
strings: [http://, https://, Authorization, Bearer, websocket, tcp, udp]
tags: [network, networking, command-and-control, downloader]
platforms: [windows, linux]
---

# Network Behavior

Search tags: network-capability network networking socket connect send recv getaddrinfo InternetOpen InternetConnect WinHttpOpen URLDownloadToFile WSAStartup http https domain ip

RAG summary: Network evidence indicates the binary may communicate with local or remote endpoints. Network capability is common and benign in many programs, but risk increases when endpoints are hard-coded, suspicious, encrypted, dynamically generated, or combined with command execution, persistence, injection, or obfuscation.

## Common indicators

- POSIX APIs: `socket`, `connect`, `send`, `recv`, `getaddrinfo`, `inet_addr`.
- Windows APIs: `InternetOpenA`, `InternetOpenW`, `InternetConnectA`, `WinHttpOpen`, `URLDownloadToFileA`, `WSAStartup`.
- Strings: `http://`, `https://`, IP addresses, ports, domains, user-agent values, API paths.
- Protocol hints: `POST`, `GET`, `Authorization`, `Bearer`, `websocket`, `dns`, `tcp`, `udp`.

## Risk interpretation

Network imports alone mean capability. Hard-coded IP addresses, unusual domains, plaintext credentials, or download-and-execute patterns are stronger evidence. Encrypted traffic is normal for TLS clients, but custom crypto plus suspicious endpoints deserves more attention.

## Stronger evidence combinations

- `network-capability` + `command-execution`: possible remote tasking, updater, or downloader.
- `network-capability` + `process-injection`: possible loader communicating before injection.
- `network-capability` + `anti-debug`: possible evasion before external communication.
- URL string + archive/decode strings + executable permissions: possible staged payload.

## False positive notes

Browsers, clients, telemetry agents, package managers, and update tools normally use network APIs. The report should focus on destination, protocol, and combined behavior.

## Analyst checklist

- Extract exact domains, URLs, IP addresses, and ports.
- Check whether the endpoint is hard-coded or derived from config.
- Look for downloaded content being written, executed, or injected.
- Mark private/local addresses differently from public remote infrastructure.
