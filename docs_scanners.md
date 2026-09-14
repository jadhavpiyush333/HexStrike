# Scanner Engine — Phase 3

Phase 3 introduces a common scanner adapter interface. Each tool is isolated behind a `Scanner` implementation and returns `ScanResult` objects.

## Integrated adapters

Nmap, ScanX, Nikto, Nuclei, WhatWeb, httpx, Gobuster, FFUF, Amass and Subfinder.

## Safety

Only run scans against systems explicitly authorized for testing. The API still validates targets against `config/targets.yaml`, applies scan profiles, rate limits and timeouts, and requires API authorization when configured.

The ScanX adapter deliberately does not assume a particular upstream CLI syntax. Set `SCANX_BIN` to the approved executable and adjust its adapter arguments after verifying the installed ScanX version.

## Normalization

The initial generic adapter preserves raw tool output as observations. Later phases will add tool-specific parsers and a normalized finding schema with evidence, confidence and severity.
