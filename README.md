# Sigma to KQL Converter

Converts [SigmaHQ](https://github.com/SigmaHQ/sigma) detection rules into **KQL (Kusto Query Language)** queries for use with Microsoft security platforms.

## What's Included

| Pipeline | Target Platform | Converted Rules |
|---|---|---|
| `microsoft_xdr` | Microsoft XDR / Defender 365 | 2,226 rules |
| `microsoft_sentinel` | Microsoft Sentinel (ASIM) | 1,550 rules |
| `azure_monitor` | Azure Monitor / Log Analytics | 1,206 rules |

Pre-converted KQL queries are in the `kql_output/` directory, organized by pipeline and mirroring the original Sigma rules folder structure.

## Repository Structure

```
Sigma_KQL/
├── converter.py              # Main conversion script
├── requirements.txt          # Python dependencies
├── sigma_rules/              # SigmaHQ rules (cloned from SigmaHQ/sigma)
│   ├── rules/                # Core detection rules
│   ├── rules-threat-hunting/ # Threat hunting rules
│   ├── rules-emerging-threats/
│   └── rules-compliance/
└── kql_output/
    ├── microsoft_xdr/        # KQL for Microsoft XDR / Defender 365
    │   ├── index.json        # Rule index (sorted by severity)
    │   └── windows/
    │       ├── process_creation/
    │       ├── file_event/
    │       ├── registry_set/
    │       └── ...
    ├── microsoft_sentinel/   # KQL for Microsoft Sentinel (ASIM)
    │   ├── index.json
    │   └── windows/...
    └── azure_monitor/        # KQL for Azure Monitor
        ├── index.json
        └── windows/...
```

## Quick Start

### Prerequisites

- Python 3.10+

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the converter

```bash
# Convert all supported rules for all platforms
python3 converter.py

# Convert only for Microsoft XDR
python3 converter.py --pipelines microsoft_xdr

# Convert only for Microsoft Sentinel
python3 converter.py --pipelines microsoft_sentinel

# Test with first 50 rules
python3 converter.py --limit 50

# Verbose output
python3 converter.py --verbose
```

### Update sigma rules and reconvert

```bash
cd sigma_rules && git pull && cd ..
python3 converter.py
```

## KQL Output Format

Each generated `.kql` file contains a header with metadata followed by the query:

```kql
// Title: Installation of WSL Kali-Linux
// Rule ID: eca8ae39-5c3c-4321-b538-9e64fe25822e
// Severity: high
// Tags: attack.execution, attack.t1059
// Category: process_creation
// Product: windows
// Pipeline: microsoft_xdr

DeviceProcessEvents
| where (FolderPath endswith "\\wsl.exe" or ProcessVersionInfoOriginalFileName =~ "wsl")
    and (ProcessCommandLine contains " --install " or ProcessCommandLine contains " -i ")
    and ProcessCommandLine contains "kali"
```

## `index.json` Format

Each pipeline output directory contains an `index.json` file for easy programmatic access:

```json
[
  {
    "id": "eca8ae39-5c3c-4321-b538-9e64fe25822e",
    "title": "Installation of WSL Kali-Linux",
    "level": "high",
    "category": "process_creation",
    "product": "windows",
    "tags": ["attack.execution", "attack.t1059"],
    "kql_file": "windows/process_creation/proc_creation_win_wsl_kali_linux_installation.kql"
  }
]
```

Rules are sorted by severity (critical → high → medium → low → informational).

## Supported Logsource Categories

| Category | XDR Table | Sentinel Table | Azure Monitor Table |
|---|---|---|---|
| `process_creation` | `DeviceProcessEvents` | `imProcessCreate` | `SecurityEvent` |
| `image_load` | `DeviceImageLoadEvents` | *(not supported)* | *(not supported)* |
| `file_event` | `DeviceFileEvents` | `imFileEvent` | `SecurityEvent` |
| `registry_set` | `DeviceRegistryEvents` | `imRegistry` | `SecurityEvent` |
| `registry_add` | `DeviceRegistryEvents` | `imRegistry` | `SecurityEvent` |
| `registry_delete` | `DeviceRegistryEvents` | `imRegistry` | `SecurityEvent` |
| `registry_event` | `DeviceRegistryEvents` | `imRegistry` | `SecurityEvent` |
| `network_connection` | `DeviceNetworkEvents` | `imNetworkSession` | `SecurityEvent` |

Rules with other logsource categories (antivirus, cloud, linux, macOS, etc.) are skipped as they don't map to these KQL tables. Use `--no-filter` to attempt conversion of all rules.

## Converter Options

```
usage: converter.py [-h] [--sigma-root PATH] [--output-dir PATH]
                    [--pipelines {azure_monitor,microsoft_sentinel,microsoft_xdr} ...]
                    [--limit N] [--no-filter] [--verbose]

Options:
  --sigma-root PATH     Root directory of sigma rules repo (default: ./sigma_rules)
  --output-dir PATH     Output directory for KQL files (default: ./kql_output)
  --pipelines           Pipelines to convert for (default: all)
  --limit N             Limit rules to convert per pipeline (for testing)
  --no-filter           Attempt conversion of all rules regardless of category
  --verbose             Enable verbose logging
```

## How It Works

This project uses [pySigma](https://github.com/SigmaHQ/pySigma) with the [pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto) backend.

The conversion pipeline:
1. **Parse** — Load each Sigma YAML rule via `SigmaCollection`
2. **Filter** — Skip rules with logsource categories not supported by the target pipeline
3. **Transform** — Apply the platform-specific processing pipeline (field name mapping, table routing)
4. **Convert** — Generate KQL via the Kusto backend
5. **Output** — Write `.kql` files preserving the original directory structure

## Credits

- Sigma rules: [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — Detection Rule License (DRL) 1.1
- pySigma: [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma)
- Kusto backend: [AttackIQ/pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto)
