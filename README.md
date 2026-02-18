# SAS-RAT Secure Remote Administration Tool — Multi-OS

Production-grade RAT with TLS encryption, HMAC authentication, and support for both Windows and Linux endpoints.

---

## Features

✅ **Multi-OS Support** — Windows (PowerShell) and Linux (Python) agents  
✅ **TLS 1.2+ Encryption** — All traffic encrypted, auto-generates self-signed certs  
✅ **HMAC-SHA256 Auth** — Pre-shared key prevents rogue clients  
✅ **Certificate Pinning** — Agents verify exact server cert (defeats MITM)  
✅ **Audit Logging** — Rotating logs of all connections and commands  
✅ **IP Allowlist** — Optional CIDR-based access control  
✅ **Auto-Reconnect** — Agents reconnect on disconnect  
✅ **GUI Interface** — Tkinter-based server with OS-aware UI  

---

## Quick Start

### 1. Start the Server (Linux)

```bash
python3 server.py
```

On first run it will generate:
- `rat_server.crt` / `rat_server.key` — TLS certificate (10-year validity)
- `rat_psk.txt` — Pre-shared key for HMAC authentication
- `rat_fingerprint.txt` — Certificate SHA-256 fingerprint

**The server will print:**
```
============================================================
  PSK  →  a1b2c3d4e5f6...
  Set $PSK = "a1b2c3d4e5f6..." in Agent_Windows.ps1 or Agent_Linux.py

  Cert fingerprint  →  ABC123DEF456...
  Set $CertThumbprint = "ABC123DEF456..." in Agent_Windows.ps1 or Agent_Linux.py
============================================================
```

### 2. Deploy Windows Agents

Edit the top of **Agent_Windows.ps1**:

```powershell
$ServerHost      = "192.168.1.50"    # Your server IP
$ServerPort      = 4444
$PSK             = "PASTE_PSK_HERE"  # From rat_psk.txt
$CertThumbprint  = "PASTE_FP_HERE"   # From rat_fingerprint.txt
```

Run on target Windows systems:

```powershell
powershell -ExecutionPolicy Bypass -File Agent_Windows.ps1
```

### 3. Deploy Linux Agents

Edit the top of **Agent_Linux.py**:

```python
SERVER_HOST      = "192.168.1.50"
SERVER_PORT      = 4444
PSK              = "PASTE_PSK_HERE"
CERT_FINGERPRINT = "PASTE_FP_HERE"
```

Run on target Linux systems:

```bash
python3 Agent_Linux.py
# Or run as background service
nohup python3 Agent_Linux.py > /dev/null 2>&1 &
```

---

## Server Options

```bash
python3 server.py --host 0.0.0.0 --port 4444
python3 server.py --psk "MyCustomKey"
python3 server.py --allow 10.0.0.0/8           # Restrict to private network
python3 server.py --allow 10.0.0.0/8 --allow 192.168.1.0/24  # Multiple subnets
python3 server.py --cert custom.crt --key custom.key
python3 server.py --no-tls                     # NOT recommended
```

---

## UI Features

### Terminal Tab
- Execute PowerShell commands on Windows agents
- Execute bash commands on Linux agents
- Command history (↑/↓ arrows)
- Auto-detects OS and adjusts prompt (`PS >` vs `$ >`)

### Processes Tab
- Live process list with CPU/RAM usage
- Filter by name
- Kill any process

### Files Tab
- Browse remote filesystem
- OS-aware path navigation (backslash on Windows, forward slash on Linux)
- Upload/download files
- Navigate by double-clicking directories

### Sysinfo Tab
- System details: OS, arch, RAM, uptime
- Shows "Administrator" for Windows, "Root" for Linux
- Python/PowerShell version

---

## Security Features

| Feature | Description |
|---------|-------------|
| **TLS Encryption** | All traffic encrypted with TLS 1.2+. Self-signed cert auto-generated on first run. |
| **Certificate Pinning** | Agents verify exact SHA-256 fingerprint of server cert, preventing MITM even with compromised CA. |
| **HMAC-SHA256 Auth** | Challenge/response authentication prevents unauthorized clients. |
| **No Credentials on Wire** | PSK never transmitted; only HMAC digest sent. Timing-attack resistant with `hmac.compare_digest`. |
| **Message Size Limits** | 50 MB hard cap prevents memory exhaustion DoS. |
| **Connection Timeouts** | 15-second auth window prevents file descriptor exhaustion. |
| **IP Allowlist** | Optional CIDR filtering blocks unauthorized source IPs. |
| **Audit Logging** | Every connection, command, and disconnect logged to `rat_audit.log` (rotating, 10 MB max). |

---

## Troubleshooting

### Agent Won't Connect

**Check PSK and fingerprint:**
```bash
# On server
cat rat_psk.txt
cat rat_fingerprint.txt
```

Make sure these match **exactly** in your agent config (case-sensitive for fingerprint).

**Check firewall:**
```bash
# Linux
sudo ufw allow 4444/tcp

# Windows
netsh advfirewall firewall add rule name="RAT Server" dir=in action=allow protocol=TCP localport=4444
```

### TLS Handshake Failed

If you see `TLS_FAIL` in the audit log:

1. Verify the fingerprint is correct in the agent
2. Try disabling cert pinning temporarily (set `$CertThumbprint = ""` or `CERT_FINGERPRINT = ""`)
3. Check if server cert expired (regenerate: `rm rat_server.crt rat_server.key && python3 server.py`)

### Font Issues on Linux

The server auto-detects available monospace fonts. If the UI looks bad:

```bash
# Install DejaVu Sans Mono (recommended)
sudo apt install fonts-dejavu-core
```

---

## Files

| File | Purpose |
|------|---------|
| `server.py` | GUI server — runs on your management machine (Linux) |
| `agent.ps1` | PowerShell agent for Windows endpoints |
| `agent.py` | Python agent for Linux endpoints |
| `rat_server.crt` | TLS certificate (auto-generated) |
| `rat_server.key` | TLS private key (auto-generated) |
| `rat_psk.txt` | Pre-shared key (auto-generated or custom) |
| `rat_fingerprint.txt` | Cert fingerprint for pinning |
| `rat_audit.log` | Audit trail (rotating logs) |

---

## Protocol

**Transport:** TCP with optional TLS 1.2+  
**Framing:** 4-byte little-endian length prefix + UTF-8 JSON  
**Auth:** HMAC-SHA256 challenge/response with PSK  

**Handshake:**
1. Server → `{"type": "challenge", "nonce": "..."}`
2. Agent → `{"type": "auth", "hmac": "..."}`
3. Server → `{"type": "auth_ok"}` (or closes connection)
4. Agent → `{"type": "register", ...metadata...}`
5. Normal command/response loop

**Commands:** `shell`, `sysinfo`, `ls`, `cd`, `ps`, `kill`, `download`, `upload`, `ping`

---

## Requirements

**Server:**
- Python 3.8+
- Tkinter (usually included with Python)
- Optional: `cryptography` package for auto cert generation (`pip install cryptography`)
- If `cryptography` not available, falls back to `openssl` CLI

**Windows Agents:**
- PowerShell 5.1+ (included in Windows 10/11)

**Linux Agents:**
- Python 3.6+
- No external dependencies (stdlib only)

---

## Bugs Fixed

This is a hardened version with 9 critical bugs and 7 security vulnerabilities fixed:

- ✅ Python 3.8/3.9 compatibility (`from __future__ import annotations`)
- ✅ Race condition in pending response dict (dual locks)
- ✅ Uncaught JSON parse errors
- ✅ Network exceptions propagating unchecked
- ✅ Invalid agents added before auth
- ✅ `os.path.dirname` broken on Windows paths from Linux server
- ✅ `lstrip()` corrupting filenames with spaces
- ✅ Hardcoded tab index (now uses frame reference)
- ✅ Status bar showing wrong host:port
- ✅ Tkinter anchor values (`"right"` → `"e"`)
- ✅ Windows-only fonts (auto-detects best monospace font)

---

## License

GNU General Public License v3.0 / Use responsibly and only on systems you own or have explicit authorization to access.
