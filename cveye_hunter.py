"""
CVEye Hunter: Local Recon Assistant

This enumeration and misconfiguration scanner was created for defenders, penetration testers, 
and power users. Inspired by real-world post-exploitation tactics, this tool helps identify 
sensitive files, system misconfigs, trust relationships, exposed data, and hidden risks 
attackers commonly seek.

"""

import os
import platform
import subprocess
import logging
import json
import re
from datetime import datetime
from pathlib import Path
import stat
import socket
import psutil

# Setup logging
LOG_FILE = f"cveye_hunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=LOG_FILE,
    filemode='w',
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO
)

results = {}

# --- Utilities ---

def run_cmd(command):
    """Run a system command and return its output or an empty string on failure."""
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        return output.strip()
    except Exception as e:
        logging.warning(f"Command failed: {command} | {e}")
        return ""

def is_writable(path):
    """Return True if the given path is writable by the current user."""
    try:
        return os.access(path, os.W_OK)
    except:
        return False

# --- Regex-based Secret Detection ---
SECRET_PATTERNS = [
    re.compile(r'[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'),  # JWT
    re.compile(r'sk_live_[0-9a-zA-Z]{24}'),  # Stripe key
    re.compile(r'(AKIA|ASIA)[0-9A-Z]{16}'),  # AWS Access Key ID
    re.compile(r'(ghp_[A-Za-z0-9]{36})'),  # GitHub token
    re.compile(r'(?<!\w)([a-z0-9]{32,})(?!\w)')  # General high-entropy
]

# --- Recon Modules ---

def scan_path_writable():
    """Scan for writable directories and binaries in the system PATH."""
    writable_bins = []
    for path in os.environ.get("PATH", "").split(os.pathsep):
        path = Path(path)
        if path.exists() and path.is_dir() and is_writable(path):
            for bin in path.glob('*'):
                if bin.is_file():
                    writable_bins.append(str(bin))
    results["writable_binaries_in_PATH"] = writable_bins
    logging.info("Writable binaries in PATH: %s", writable_bins)

def scan_env_vars():
    """Search environment variables for values that match sensitive regex patterns."""
    hits = {}
    for key, val in os.environ.items():
        for pattern in SECRET_PATTERNS:
            if pattern.search(val):
                hits[key] = val
    results["regex_env_secrets"] = hits
    logging.info("Secrets found in environment: %s", list(hits.keys()))

def scan_shell_history():
    """Look through shell history files for secrets or commands containing sensitive data."""
    home = str(Path.home())
    history_files = [
        ".bash_history", ".zsh_history",
        "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    ]
    findings = []
    for f in history_files:
        fpath = Path(home) / f
        if fpath.exists():
            with open(fpath, 'r', errors='ignore') as file:
                for line in file:
                    for pattern in SECRET_PATTERNS:
                        if pattern.search(line):
                            findings.append({"file": str(fpath), "line": line.strip()})
    results["shell_secrets"] = findings
    logging.info("Secrets found in shell history: %d", len(findings))

def scan_dev_secrets():
    """Scan for sensitive files in the home directory commonly used in development or cloud environments."""
    home = str(Path.home())
    sensitive_files = [".git-credentials", ".aws/credentials", ".npmrc", ".env"]
    exposures = []
    for fname in sensitive_files:
        path = Path(home) / fname
        if path.exists():
            content = path.read_text(errors='ignore')[:500]
            for pattern in SECRET_PATTERNS:
                if pattern.search(content):
                    exposures.append({"file": str(path), "sample": content})
    results["cloud_dev_exposures"] = exposures
    logging.info("Sensitive dev/cloud files found: %d", len(exposures))

def scan_ssh_configs():
    """Check SSH directory for private/public keys and flag ones with improper permissions."""
    ssh_dir = Path.home() / ".ssh"
    findings = []
    if ssh_dir.exists():
        for file in ssh_dir.iterdir():
            if file.suffix in ['.pub', '', '.pem']:
                perms = oct(file.stat().st_mode & 0o777)
                if perms != '0o600':
                    findings.append({"file": str(file), "permissions": perms})
    results["ssh_key_issues"] = findings
    logging.info("SSH misconfigs found: %d", len(findings))

def scan_ports_pids():
    """List open listening ports and map them to their corresponding process IDs and binaries."""
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                proc = psutil.Process(conn.pid)
                ports.append({
                    "port": conn.laddr.port,
                    "pid": conn.pid,
                    "exe": proc.exe(),
                    "name": proc.name()
                })
            except Exception as e:
                ports.append({"port": conn.laddr.port, "pid": conn.pid, "error": str(e)})
    results["open_ports"] = ports
    logging.info("Listening ports and associated processes found: %d", len(ports))

def scan_startup():
    """Detect autorun and startup script entries depending on the operating system."""
    entries = []
    system = platform.system()
    if system == 'Windows':
        output = run_cmd("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        entries = output.splitlines()
    else:
        for f in ["~/.config/autostart", "/etc/systemd/system"]:
            path = Path(os.path.expanduser(f))
            if path.exists():
                entries.extend([str(p) for p in path.glob("**/*") if p.is_file()])
        entries.extend(run_cmd("crontab -l").splitlines())
    results["startup_entries"] = entries
    logging.info("Startup entries detected: %d", len(entries))

def scan_users():
    """List all system users and their default shells (UNIX) or active sessions (Windows)."""
    users = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    users.append({"user": parts[0], "shell": parts[6]})
    except:
        users = [u.name() for u in psutil.users()]
    results["system_users"] = users
    logging.info("Users enumerated: %d", len(users))

def scan_browser():
    """Check for presence of browser config directories that might contain saved logins or cookies."""
    browser_paths = [".mozilla", ".config/google-chrome", ".config/BraveSoftware"]
    found = []
    for bp in browser_paths:
        path = Path.home() / bp
        if path.exists():
            found.append(str(path))
    results["browser_artifacts"] = found
    logging.info("Browser paths detected: %d", len(found))

def scan_mounted_drives():
    """Detect mounted cloud, network, or virtual drives (e.g., SMB, NFS, FUSE)."""
    lines = run_cmd("mount").splitlines()
    matches = [line for line in lines if any(x in line for x in ["nfs", "smb", "fuse", "google", "onedrive", "dropbox"])]
    results["mounted_drives"] = matches
    logging.info("Mounted network/cloud drives found: %d", len(matches))

# --- Save Output ---

def save_report():
    """Write the complete results dictionary to a timestamped JSON file."""
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    outpath = f"cveyehunter_advanced_{now}.json"
    with open(outpath, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[+] Full report saved to: {outpath}")

# --- Main Execution ---

def main():
    print("[+] Running CVEye Hunter (Advanced Edition)\n")
    scan_path_writable()
    scan_env_vars()
    scan_shell_history()
    scan_dev_secrets()
    scan_ssh_configs()
    scan_ports_pids()
    scan_startup()
    scan_users()
    scan_browser()
    scan_mounted_drives()
    save_report()
    print("[+] Recon complete. Review the JSON report for findings.")

if __name__ == '__main__':
    main()
