# CVEye Hunter - Local Recon Assistant

**Author:** [kmukoo101](https://github.com/kmukoo101)  
**License:** MIT

---

## What is CVEye Hunter?

This is a local reconnaissance and misconfiguration detection tool that simulates real-world adversary behaviors to help:

- Defenders
- Pentesters & Red Teamers
- Security Analysts
- Developers & System Admins

### Sample Use Cases

- Detect secrets left behind on shared/dev machines
- Validate hardened system images before deployment
- Simulate post-exploitation recon after access
- Baseline clean vs. compromised system state
- Blue team hygiene audits

Identify and fix common security gaps before attackers do.

---

## Features

- Writable PATH & binary checks
- Environment variable secret detection (regex-based)
- Shell history secret scanning
- Dev/cloud secrets (.env, .aws, etc.)
- SSH key permission issues
- Open port to PID & executable mapping
- Autorun & startup service detection
- Local user enumeration
- Browser config & saved session detection
- Mounted drive detection (NFS, SMB, Dropbox, etc.)
- Saves detailed JSON report
- Optional GUI with HTML/PDF export

---

## GUI Mode

Launch with a full graphical interface to:

- Start a full scan
- View scan output in real-time
- Export results to HTML or PDF

---

## Getting Started

### Requirements

- Python 3.7+
- Cross-platform (Linux, macOS, Windows)

### Install dependencies

```bash
pip install psutil fpdf
```

### Run (GUI or CLI)

Edit in script (bottom):

```python
use_gui = True  # Set to False for CLI mode
```

Then run:

```bash
python cveye_hunter.py
```

---

## Output

- Saves a full recon report to:  
  `cveyehunter_advanced_YYYYMMDD_HHMMSS.json`
- Logs activity to:  
  `cveye_hunter_YYYYMMDD_HHMMSS.log`
- Optional: export to HTML or PDF via GUI

---

## Legal Disclaimer

This tool is meant for educational and defensive purposes only. Don't use on systems you don't own or have permission to scan.

