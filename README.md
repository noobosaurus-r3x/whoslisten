# whoslisten

A Linux network service discovery tool that maps processes to listening ports and detects suspicious activity.
Working WIP.

## Features

- Maps all TCP/UDP services to their processes
- Detects potentially malicious processes (crypto miners, backdoors, reverse shells)
- Real-time monitoring with change detection
- Process details: SHA256 hashes, capabilities, user context
- Export to JSON/CSV/XML
- Rich terminal output with colors

## Quick Start

```bash
# Basic scan (complete visibility)
sudo ./whoslisten.py

# Basic scan (your processes only)
./whoslisten.py

# Monitor in real-time
sudo ./whoslisten.py --monitor

# Show only suspicious services
sudo ./whoslisten.py --suspicious

# Export results
./whoslisten.py --export services.json
```

## Installation

```bash
# Clone the repo
git clone https://github.com/noobosaurus-r3x/whoslisten
cd whoslisten

# Make executable
chmod +x whoslisten.py

# Optional: Better output
pip install rich
```

**Privileges:** 
- **With sudo:** Complete process visibility and accurate threat detection
- **Without sudo:** Limited to processes you own, may miss threats
- **Alternative:** Use capabilities: `sudo setcap cap_sys_ptrace+ep whoslisten.py`

⚠️ **Security note:** Only run as root if you trust the script and need complete system visibility.

## Usage

```bash
# Basic options
sudo ./whoslisten.py                    # Scan all services
sudo ./whoslisten.py --proto tcp        # TCP only
sudo ./whoslisten.py --fast             # Skip SHA256 hashes
sudo ./whoslisten.py --no-color         # Plain output

# Monitoring
sudo ./whoslisten.py --monitor          # Continuous monitoring
sudo ./whoslisten.py --monitor --quiet  # Less verbose

# Export
sudo ./whoslisten.py --export data.json # JSON format
sudo ./whoslisten.py --export data.csv  # CSV format
```

## What's "Suspicious"?

- High ports (>49152) from unexpected processes
- Crypto miners (`xmrig`, `cpuminer`)
- Network tools (`netcat`, `socat`) 
- Suspicious names (`backdoor`, `shell`)
- Reverse shell patterns
- Malicious commands (`wget | sh`)

Common legitimate processes are filtered out automatically.

