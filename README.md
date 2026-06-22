# NextEnum

NextEnum is a Python command-line tool that reads Nmap scan results and helps you decide what to enumerate next.

It is built as a learning tool for cybersecurity students, junior pentesters, CTF players, and people practicing in authorized lab environments.

NextEnum does not exploit targets or automate attacks. It focuses on parsing scan results, explaining detected services, showing useful enumeration steps, and giving a recommended order to continue manual testing.

---

## What NextEnum Does

NextEnum can:

- Read Nmap normal text and XML output files.
- Extract open ports and detected services.
- Normalize common service names, such as `netbios-ssn` to `smb`.
- Extract product, version, and extra service information.
- Extract Nmap NSE script results.
- Show a clean service summary table.
- Show detailed script output.
- Show service-specific enumeration guides.
- Recommend which services to enumerate first.

---

## Who It Is For

NextEnum is useful for:

- Cybersecurity students.
- Junior penetration testers.
- CTF players.
- People learning enumeration methodology.

The goal is to make Nmap results easier to understand and turn them into a clear next step.

---

## Current Features

### Nmap File Parsing

NextEnum supports:

```bash
-oN normal text output
-oX XML output
```

Example Nmap scans:

```bash
nmap [OPTIONS] -oN scans/target_scan.txt TARGET_IP
nmap [OPTIONS] -oX scans/target_scan.xml TARGET_IP
```

### Service Summary

Show a clean table of detected services:

```bash
nextenum -f scans/target_scan.xml
```

### Script Output

Show the normal service table and detailed NSE script results:

```bash
nextenum -f scans/target_scan.xml --show-scripts
```

Show only detailed NSE script results:

```bash
nextenum -f scans/target_scan.xml --only-scripts
```

### Enumeration Guides

Show guidance for all detected services:

```bash
nextenum -f scans/target_scan.xml --guide
```

Show guidance for a specific service:

```bash
nextenum -f scans/target_scan.xml --guide http
```

Show guidance for a specific port:

```bash
nextenum -f scans/target_scan.xml --guide 80
```

### Recommendations

Show a recommended enumeration order:

```bash
nextenum -f scans/target_scan.xml -r
```

or:

```bash
nextenum -f scans/target_scan.xml --recommend
```

### Target Override

Override the target shown in generated guide commands:

```bash
nextenum -f scans/target_scan.xml -t 10.10.10.5 --guide http
```

---

## Supported Service Guides

Current service guides include:

- HTTP / HTTPS
- FTP
- SSH
- SMB
- DNS
- SMTP
- NFS
- MySQL
- PostgreSQL
- RDP

Each guide includes:

- What the service is.
- Why it matters.
- Useful Nmap scripts.
- Suggested enumeration steps.
- Things to look for.
- Next steps based on findings.
- Beginner notes.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/hussaaiin/NextEnum.git
cd NextEnum
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

Check that the command works:

```bash
nextenum -h
```

---

## Usage Examples

Run a basic summary:

```bash
nextenum -f examples/sample_scan.xml
```

Show recommendations:

```bash
nextenum -f examples/sample_scan.xml -r
```

Show the HTTP guide:

```bash
nextenum -f examples/sample_scan.xml --guide http
```

Show the guide for port 445:

```bash
nextenum -f examples/sample_scan.xml --guide 445
```

Show only script results:

```bash
nextenum -f examples/sample_scan.xml --only-scripts
```

---

## Help Menus

Short help:

```bash
nextenum -h
```

Detailed help:

```bash
nextenum --help
```

---

## Project Goal

The main goal is to help users move from raw Nmap output to a clear manual enumeration plan. It is not meant to replace learning or automate exploitation. It is meant to support better methodology.

More improvements may be added later, such as export options, better scoring rules, more service guides, or a command history helper.

