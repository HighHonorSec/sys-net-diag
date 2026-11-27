# sys-net-diag

Cross-platform Python CLI tool for **L1 IT Support** and **Network Troubleshooting** on Windows, Linux, and macOS.

## Features

- **System Health Checks (`psutil`)**
  - CPU utilization, physical/logical core counts, and load averages (where supported)
  - RAM & swap utilization and available memory
  - Local disk partition usage (with permission/CD-ROM safety) or custom path inspection
  - OS details, UTC boot timestamp, and human-readable uptime
  - Automatic `OK` / `WARN` / `CRIT` threshold triage
- **Network Diagnostics**
  - Local primary IPv4 address, active network interfaces, and cross-platform default gateway detection (`route print` on Windows, `/proc/net/route` / `ip route` on Linux, `route -n get default` on macOS)
  - DNS resolution checks with resolved IP addresses and lookup latency (ms)
  - Cross-platform ICMP ping latency (`min`/`avg`/`max` ms) and packet loss percentage
  - Configurable TCP port connectivity checks with common service labels (HTTP, HTTPS, SSH, RDP, SMB, etc.)
- **CLI & Reporting (`argparse`)**
  - Clean console output in plain text (`--format text`) or JSON (`--format json`)
  - Export diagnostic reports to `.txt` or `.json` via `-o` / `--export`
  - Selective execution (`--skip-system`, `--skip-network`) and strict exit codes (`--strict`)

## Installation

```bash
git clone <repository-url>
cd sys-net-diag
python -m venv .venv
```

Activate the virtual environment and install dependencies:

- **Windows (PowerShell):**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  ```
- **Linux / macOS:**
  ```bash
  source .venv/bin/activate
  pip install -r requirements.txt
  ```

Optional editable install to register the `sys-net-diag` command directly:

```bash
pip install -e .
```

## Usage

Run directly as a module or script:

```bash
python -m sys_net_diag
# or
python sys_net_diag.py
```

### Common L1 Support Examples

Run default diagnostics (system health + `google.com` DNS/ports `80, 443` + `8.8.8.8` ping):

```bash
python -m sys_net_diag
```

Check internal/custom endpoints and RDP/SSH/HTTPS ports, then export a `.txt` report:

```bash
python -m sys_net_diag --dns-host portal.example.com --ping-host 1.1.1.1 8.8.8.8 --port-host portal.example.com --ports 22,80,443,3389 -o triage_report.txt
```

Export structured `.json` quietly for ticket attachment or automation:

```bash
python -m sys_net_diag --quiet --export report.json
```

Run only network diagnostics and print JSON to stdout:

```bash
python -m sys_net_diag --skip-system --format json
```

### CLI Options

| Flag | Description | Default |
| --- | --- | --- |
| `--skip-system` | Skip CPU, RAM, Disk, and Uptime checks | `False` |
| `--cpu-interval` | CPU sampling interval in seconds | `0.2` |
| `--disk-path` | Check a specific filesystem path/drive | All local partitions |
| `--skip-network` | Skip Local IP/Gateway, DNS, Ping, and Port checks | `False` |
| `--dns-host` | Hostname(s) to resolve via DNS | `google.com` |
| `--ping-host` | Host(s) or IP(s) to ping via ICMP | `8.8.8.8` |
| `--ping-count` | ICMP packets per target | `4` |
| `--port-host` | Target host for TCP port checks | `google.com` |
| `--ports` | TCP port(s), space- or comma-separated | `80 443` |
| `--timeout` | Timeout in seconds for ping and TCP ports | `3.0` |
| `--format` | Console output format (`text` or `json`) | `text` |
| `-o`, `--export` | Export report to a `.txt` or `.json` file | `None` |
| `--export-format` | Override export format (`txt` or `json`) | Inferred from extension |
| `-q`, `--quiet` | Suppress stdout report output | `False` |
| `--strict` | Exit with code `1` if overall status is not `OK` | `False` |
| `--version` | Show tool version and exit | — |

## Running Tests

Unit tests use `pytest` with mocked network calls (`socket`, `subprocess`, `psutil` network interfaces):

```bash
pytest -v
```
