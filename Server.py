#!/usr/bin/env python3
"""
Secure Remote Administration Tool — GUI Server
Requires: Python 3.8+
Optional: pip install cryptography   (for automatic TLS cert generation)

On first run the server creates:
  rat_server.crt / rat_server.key  — self-signed TLS certificate (10 years)
  rat_psk.txt                      — pre-shared key for agent HMAC authentication
  rat_fingerprint.txt              — cert SHA-256 fingerprint to paste into agent.ps1
  rat_audit.log                    — rotating audit log of all connections & commands

Usage:
  python server.py                              # 0.0.0.0:4444, auto TLS + PSK
  python server.py --port 5555
  python server.py --psk "MySecret"            # explicit pre-shared key
  python server.py --allow 10.0.0.0/8          # restrict to subnet (repeatable)
  python server.py --cert my.crt --key my.key  # use existing certificate
  python server.py --no-tls                    # disable TLS (NOT recommended)
"""
# ── BUG FIX #1: Python 3.8/3.9 compatibility ─────────────────
# The X | Y union-type annotation syntax requires Python 3.10+.
# Without this import, the module crashes immediately on Python 3.8/3.9
# with: TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'
# With it, all annotations are treated as strings and never evaluated at runtime.
from __future__ import annotations

import argparse, base64, hashlib, hmac as _hmac, json, logging, os
import secrets, socket, ssl, struct, threading, uuid
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
DEFAULT_HOST      = "0.0.0.0"
DEFAULT_PORT      = 4444
MAX_MSG_BYTES     = 50 * 1024 * 1024   # 50 MB hard cap — prevents memory DoS
AUTH_TIMEOUT_SECS = 15                  # seconds to complete TLS + HMAC handshake
CERT_FILE         = "rat_server.crt"
KEY_FILE          = "rat_server.key"
PSK_FILE          = "rat_psk.txt"
FPRINT_FILE       = "rat_fingerprint.txt"
LOG_FILE          = "rat_audit.log"

C = {
    "base":    "#1e1e2e", "mantle":  "#181825", "crust":   "#11111b",
    "surface0":"#313244", "surface1":"#45475a", "surface2":"#585b70",
    "overlay0":"#6c7086", "overlay1":"#7f849c", "text":    "#cdd6f4",
    "subtext": "#a6adc8", "blue":    "#89b4fa", "lavender":"#b4befe",
    "mauve":   "#cba6f7", "red":     "#f38ba8", "peach":   "#fab387",
    "yellow":  "#f9e2af", "green":   "#a6e3a1", "teal":    "#94e2d5",
    "sky":     "#89dceb",
}



# ════════════════════════════════════════════════════════════════
#  Font detection — MONO is Windows-only; pick best
#  available monospace font from what the system actually has.
# ════════════════════════════════════════════════════════════════

def _pick_mono() -> str:
    """Return the best available monospace font family on this system."""
    try:
        import tkinter.font as tkfont
        import tkinter as _tk
        _r = _tk.Tk(); _r.withdraw()
        available = set(tkfont.families())
        _r.destroy()
    except Exception:
        available = set()
    for candidate in (
        "Courier New",  # Windows / some Linux installs
        "DejaVu Sans Mono",   # default on Debian/Ubuntu/Kali
        "Liberation Mono",    # RHEL/Fedora/CentOS
        "Hack",               # popular dev font
        "Fira Mono",
        "Cascadia Mono",
        "JetBrains Mono",
        "Source Code Pro",
        "Roboto Mono",
        "Courier 10 Pitch",   # common Linux fallback
        "Courier",
        "Monospace",          # GTK generic alias — always resolves
        "fixed",
    ):
        if candidate in available:
            return candidate
    return "TkFixedFont"      # guaranteed tkinter fallback


MONO = _pick_mono()


# ════════════════════════════════════════════════════════════════
#  TLS certificate management
# ════════════════════════════════════════════════════════════════

def _pem_fingerprint(pem_path: str) -> str:
    """
    Return uppercase hex SHA-256 of the DER-encoded certificate.
    Uses only stdlib — no external package needed for this step.
    The value matches .NET's X509Certificate2.GetCertHashString("SHA256").
    """
    with open(pem_path, "rb") as f:
        pem = f.read()
    b64_lines = []
    inside = False
    for line in pem.splitlines():
        if b"BEGIN CERTIFICATE" in line:
            inside = True
            continue
        if b"END CERTIFICATE" in line:
            break
        if inside:
            b64_lines.append(line.strip())
    der = base64.b64decode(b"".join(b64_lines))
    return hashlib.sha256(der).hexdigest().upper()


def _gen_cert_cryptography(cert_path: str, key_path: str) -> str:
    """Generate a 4096-bit RSA self-signed cert via the 'cryptography' package."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt, ipaddress as ipa

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RATServer")])

    san_ips = {ipa.IPv4Address("127.0.0.1")}
    try:
        san_ips.add(ipa.IPv4Address(socket.gethostbyname(socket.gethostname())))
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow())
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost")] + [x509.IPAddress(ip) for ip in san_ips]
        ), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return _pem_fingerprint(cert_path)


def _gen_cert_openssl(cert_path: str, key_path: str) -> str:
    """Generate cert via the openssl CLI (fallback when cryptography not installed)."""
    import subprocess
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_path, "-out", cert_path,
        "-days", "3650", "-nodes", "-subj", "/CN=RATServer",
    ], check=True, capture_output=True)
    return _pem_fingerprint(cert_path)


def ensure_cert(cert_path: str, key_path: str) -> Optional[str]:
    """
    Return cert SHA-256 fingerprint, generating the cert if needed.
    Returns None if cert generation fails (TLS will be disabled).
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return _pem_fingerprint(cert_path)
    print("[*] Generating TLS certificate (this may take a moment)...")
    for gen in (_gen_cert_cryptography, _gen_cert_openssl):
        try:
            fp = gen(cert_path, key_path)
            print(f"[+] Certificate generated  ({cert_path})")
            return fp
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] cert gen failed: {e}")
    print("[!] Could not generate TLS cert.")
    print("[!] Install 'cryptography' (pip install cryptography) or openssl CLI.")
    return None


def ensure_psk(psk_file: str, explicit: Optional[str]) -> str:
    """Return PSK: explicit arg > saved file > auto-generate."""
    if explicit:
        return explicit
    if os.path.exists(psk_file):
        with open(psk_file) as f:
            return f.read().strip()
    psk = secrets.token_hex(32)
    with open(psk_file, "w") as f:
        f.write(psk)
    print(f"[+] Auto-generated PSK saved to {psk_file}")
    return psk


# ════════════════════════════════════════════════════════════════
#  Audit logging
# ════════════════════════════════════════════════════════════════

def _setup_audit_log() -> logging.Logger:
    log = logging.getLogger("rat_audit")
    log.setLevel(logging.INFO)
    if not log.handlers:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(fh)
    return log


AUDIT = _setup_audit_log()


# ════════════════════════════════════════════════════════════════
#  Network layer
# ════════════════════════════════════════════════════════════════

class Agent:
    """Represents one authenticated, connected endpoint."""

    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        self.conn         = conn
        self.addr         = addr
        self.id           = uuid.uuid4().hex[:8]
        self.hostname     = "Unknown"
        self.username     = "Unknown"
        self.os           = "Unknown"
        self.arch         = "Unknown"
        self.ip           = addr[0]
        self.is_admin     = False
        self.ps_ver       = "?"
        self.os_type      = "windows"  # "windows" or "linux"
        self.connected_at = datetime.now()
        # BUG FIX #2: two separate locks — one for the socket, one for the
        # pending-response dict.  Without the pending lock, send_command() and
        # deliver_response() race on _pending from two different threads.
        self._send_lock  = threading.Lock()
        self._pend_lock  = threading.Lock()
        self._pending: Dict[str, dict] = {}

    # ── Low-level framed I/O ─────────────────────────────────

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Read exactly n bytes or return None on disconnect / error."""
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.conn.recv(n - len(buf))
            # BUG FIX #4: catch network errors rather than letting them
            # propagate and silently kill the handler thread
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def recv_msg(self) -> Optional[dict]:
        """Read one length-prefixed JSON message."""
        hdr = self._recv_exact(4)
        if not hdr:
            return None
        length = struct.unpack("<I", hdr)[0]
        # SECURITY FIX #4: hard cap on message size — prevents memory DoS.
        # Without this a client can send length=0xFFFFFFFF and exhaust RAM.
        if length == 0 or length > MAX_MSG_BYTES:
            AUDIT.warning("BAD_LENGTH  len=%d  ip=%s", length, self.addr[0])
            return None
        raw = self._recv_exact(length)
        if not raw:
            return None
        # BUG FIX #3: catch malformed JSON from misbehaving / malicious clients
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None

    def send_msg(self, data: dict) -> bool:
        """Send one length-prefixed JSON message. Returns False on error."""
        # BUG FIX #4: catch send errors; callers must not have unchecked exceptions
        try:
            payload = json.dumps(data).encode("utf-8")
            header  = struct.pack("<I", len(payload))
            with self._send_lock:
                self.conn.sendall(header + payload)
            return True
        except (OSError, ssl.SSLError):
            return False

    # ── Command / response ────────────────────────────────────

    def send_command(self, command: str, args=None, **kwargs) -> Tuple[str, threading.Event]:
        mid = uuid.uuid4().hex[:8]
        msg = {"id": mid, "command": command}
        if args is not None:
            msg["args"] = args
        msg.update(kwargs)
        ev = threading.Event()
        with self._pend_lock:
            self._pending[mid] = {"event": ev, "response": None}
        self.send_msg(msg)
        return mid, ev

    def deliver_response(self, mid: str, response: dict):
        with self._pend_lock:
            entry = self._pending.get(mid)
        if entry:
            entry["response"] = response
            entry["event"].set()

    def wait_response(self, mid: str, timeout: float = 30) -> Optional[dict]:
        with self._pend_lock:
            entry = self._pending.get(mid)
        if not entry:
            return None
        hit = entry["event"].wait(timeout)
        with self._pend_lock:
            self._pending.pop(mid, None)
        return entry["response"] if hit else None


class RATServer:
    """
    Multi-agent TCP server with TLS encryption and HMAC-PSK authentication.

    Authentication handshake:
      1. Server  → {"type": "challenge", "nonce": "<32-byte hex>"}
      2. Client  → {"type": "auth",      "hmac":  "<HMAC-SHA256(psk, nonce_bytes) hex>"}
      3. Server  → {"type": "auth_ok"}    (if HMAC matches, else closes connection)
      4. Client  → {"type": "register",  ...metadata...}
      5. Normal command/response loop begins
    """

    def __init__(
        self,
        host: str,
        port: int,
        psk: str,
        tls_context: Optional[ssl.SSLContext] = None,
        allow_nets: Optional[List[IPv4Network]] = None,
    ):
        self.host        = host
        self.port        = port
        self._psk        = psk.encode()      # store as bytes; never log raw value
        self.tls_context = tls_context
        self.allow_nets  = allow_nets or []
        self._agents: Dict[str, Agent] = {}
        self._lock       = threading.Lock()
        self._cbs: List[Callable] = []
        self._sock: Optional[socket.socket] = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        threading.Thread(target=self._accept_loop, daemon=True, name="accept").start()

    # ── IP allowlist check ───────────────────────────────────

    def _ip_allowed(self, ip: str) -> bool:
        """SECURITY: Return False if this IP is not in the configured allowlist."""
        if not self.allow_nets:
            return True
        try:
            addr = ip_address(ip)
            return any(addr in net for net in self.allow_nets)
        except ValueError:
            return False

    # ── Accept loop ──────────────────────────────────────────

    def _accept_loop(self):
        while True:
            try:
                raw_conn, addr = self._sock.accept()
            except OSError:
                break

            # SECURITY: IP check before reading any bytes
            if not self._ip_allowed(addr[0]):
                AUDIT.warning("REJECT_IP  ip=%s", addr[0])
                raw_conn.close()
                continue

            # SECURITY: auth timeout — prevents fd exhaustion from stale connections
            raw_conn.settimeout(AUTH_TIMEOUT_SECS)
            threading.Thread(
                target=self._handle,
                args=(raw_conn, addr),
                daemon=True,
                name=f"agent-{addr[0]}",
            ).start()

    # ── Per-connection handler ────────────────────────────────

    def _handle(self, raw_conn: socket.socket, addr: Tuple[str, int]):
        conn = raw_conn

        # SECURITY: TLS upgrade
        if self.tls_context:
            try:
                conn = self.tls_context.wrap_socket(raw_conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                AUDIT.warning("TLS_FAIL  ip=%s  err=%s", addr[0], e)
                raw_conn.close()
                return

        agent = Agent(conn, addr)
        try:
            # SECURITY: HMAC challenge/response before accepting any data
            if not self._authenticate(agent):
                conn.close()
                return

            # BUG FIX #5: remove the auth timeout now that the agent is trusted
            conn.settimeout(None)

            # BUG FIX #5: validate the registration message before adding to agent list
            msg = agent.recv_msg()
            if not msg or msg.get("type") != "register":
                AUDIT.warning("BAD_REGISTER  ip=%s", addr[0])
                conn.close()
                return

            # Sanitise and cap field lengths from untrusted input
            agent.hostname = str(msg.get("hostname", "Unknown"))[:64]
            agent.username = str(msg.get("username", "Unknown"))[:64]
            agent.os       = str(msg.get("os",       "Unknown"))[:128]
            agent.arch     = str(msg.get("arch",     "Unknown"))[:32]
            agent.ip       = str(msg.get("ip",       addr[0]))[:45]
            
            # Detect OS type from OS string
            os_lower = agent.os.lower()
            if "linux" in os_lower or "unix" in os_lower or "darwin" in os_lower:
                agent.os_type = "linux"
                # Python agent sends is_root and python_ver
                agent.is_admin = bool(msg.get("is_root", False))
                agent.ps_ver   = str(msg.get("python_ver", "?"))[:32]
            else:
                agent.os_type = "windows"
                # PowerShell agent sends is_admin and ps_ver
                agent.is_admin = bool(msg.get("is_admin", False))
                agent.ps_ver   = str(msg.get("ps_ver", "?"))[:32]

            # BUG FIX #5: only add to visible agent dict AFTER auth + valid register
            with self._lock:
                self._agents[agent.id] = agent

            AUDIT.info("CONNECT  user=%s  host=%s  ip=%s  os=%s  admin=%s",
                       agent.username, agent.hostname, agent.ip,
                       agent.os, agent.is_admin)
            self._fire("connect", agent)

            # Command loop
            while True:
                msg = agent.recv_msg()
                if msg is None:
                    break
                if msg.get("type") == "response" and "id" in msg:
                    agent.deliver_response(msg["id"], msg)

        except Exception:
            pass
        finally:
            with self._lock:
                self._agents.pop(agent.id, None)
            AUDIT.info("DISCONNECT  user=%s  host=%s  ip=%s",
                       agent.username, agent.hostname, agent.ip)
            self._fire("disconnect", agent)
            try:
                conn.close()
            except Exception:
                pass

    def _authenticate(self, agent: Agent) -> bool:
        """
        SECURITY: HMAC-SHA256 challenge/response authentication.
        - Prevents rogue clients from masquerading as legitimate agents.
        - Uses hmac.compare_digest to avoid timing-oracle side-channel attacks.
        """
        nonce = secrets.token_bytes(32)
        if not agent.send_msg({"type": "challenge", "nonce": nonce.hex()}):
            return False
        msg = agent.recv_msg()
        if not msg or msg.get("type") != "auth":
            AUDIT.warning("AUTH_FAIL  ip=%s  reason=wrong_type", agent.addr[0])
            return False
        try:
            claimed = bytes.fromhex(msg["hmac"])
        except (KeyError, ValueError):
            AUDIT.warning("AUTH_FAIL  ip=%s  reason=bad_hmac_format", agent.addr[0])
            return False
        expected = _hmac.new(self._psk, nonce, hashlib.sha256).digest()
        if not _hmac.compare_digest(expected, claimed):
            AUDIT.warning("AUTH_FAIL  ip=%s  reason=hmac_mismatch", agent.addr[0])
            return False
        agent.send_msg({"type": "auth_ok"})
        return True

    def _fire(self, ev: str, agent: Agent):
        for cb in self._cbs:
            try:
                cb(ev, agent)
            except Exception:
                pass

    def on_event(self, cb: Callable):
        self._cbs.append(cb)

    def agents(self) -> List[Agent]:
        with self._lock:
            return list(self._agents.values())

    def get(self, aid: str) -> Optional[Agent]:
        with self._lock:
            return self._agents.get(aid)

    def audit_cmd(self, agent: Agent, command: str, args: str = ""):
        AUDIT.info("CMD  user=%s  host=%s  cmd=%s  args=%.200s",
                   agent.username, agent.hostname, command, args)


# ════════════════════════════════════════════════════════════════
#  GUI
# ════════════════════════════════════════════════════════════════

class App:
    def __init__(
        self,
        root: tk.Tk,
        host: str,
        port: int,
        psk: str,
        tls_context: Optional[ssl.SSLContext],
        fingerprint: Optional[str],
        allow_nets: Optional[List[IPv4Network]],
    ):
        self.root = root
        self.root.title("RAT Server  //  Remote Administration Tool")
        self.root.geometry("1280x820")
        self.root.minsize(1000, 640)
        self.root.configure(bg=C["base"])

        self._host        = host
        self._port        = port
        self._tls         = tls_context is not None
        self._fingerprint = fingerprint

        self.server = RATServer(host, port, psk, tls_context, allow_nets)
        self.server.on_event(self._on_agent_event)

        self._sel_id: Optional[str]    = None
        self._tree_map: Dict[str, str] = {}
        self._cmd_history: List[str]   = []
        self._hist_idx: int            = -1
        self._proc_cache: List         = []
        # BUG FIX #8: store frame reference instead of hardcoded index 3
        self._sysinfo_tab_frame: Optional[tk.Frame] = None

        self._apply_styles()
        self._build_ui()
        self._start_clock()

        self.server.start()
        tls_badge = "TLS ✓" if self._tls else "⚠ NO TLS"
        self._log(f"[+] Listening on {host}:{port}  [{tls_badge}]",
                  "success" if self._tls else "warn")
        if fingerprint:
            self._log(f"[*] Cert fingerprint: {fingerprint}", "dim")
            self._log("[*] Paste above value into $CertThumbprint in agent.ps1", "dim")
        psk_hint = psk[:8] + "…" + psk[-4:] if len(psk) > 16 else "***"
        self._log(f"[*] PSK hint: {psk_hint}  (full key in {PSK_FILE})", "dim")
        self._log("[*] Waiting for agents…", "dim")

    # ── ttk styling ───────────────────────────────────────────

    def _apply_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=C["base"], foreground=C["text"],
                     font=(MONO, 10), borderwidth=0, relief="flat")
        s.configure("Treeview", background=C["mantle"], foreground=C["text"],
                     fieldbackground=C["mantle"], rowheight=26,
                     borderwidth=0, relief="flat")
        s.configure("Treeview.Heading", background=C["surface0"], foreground=C["blue"],
                     font=(MONO, 10, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", C["surface0"])],
              foreground=[("selected", C["lavender"])])
        s.configure("TButton", background=C["surface0"], foreground=C["text"],
                     font=(MONO, 10), padding=(8, 4), relief="flat")
        s.map("TButton",
              background=[("active", C["surface1"]), ("pressed", C["surface2"])])
        s.configure("Accent.TButton", background=C["blue"], foreground=C["crust"],
                     font=(MONO, 10, "bold"), padding=(10, 4))
        s.map("Accent.TButton", background=[("active", C["lavender"])])
        s.configure("Danger.TButton", background=C["red"], foreground=C["crust"],
                     font=(MONO, 10, "bold"), padding=(8, 4))
        s.map("Danger.TButton", background=[("active", "#ff9999")])
        s.configure("TFrame", background=C["base"])
        s.configure("TLabel", background=C["base"], foreground=C["text"])
        s.configure("TEntry", fieldbackground=C["surface0"], foreground=C["text"],
                     insertcolor=C["text"], borderwidth=1, relief="solid")
        s.configure("TNotebook", background=C["base"], tabmargins=(2, 4, 0, 0),
                     borderwidth=0)
        s.configure("TNotebook.Tab", background=C["surface0"], foreground=C["subtext"],
                     padding=(14, 5), font=(MONO, 10))
        s.map("TNotebook.Tab",
              background=[("selected", C["base"])],
              foreground=[("selected", C["blue"])])
        s.configure("TScrollbar", background=C["surface0"], troughcolor=C["mantle"],
                     arrowcolor=C["overlay0"], borderwidth=0, relief="flat")
        s.map("TScrollbar", background=[("active", C["surface1"])])

    # ── Layout ────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        topbar = tk.Frame(self.root, bg=C["crust"], height=42)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="◈  RAT SERVER", bg=C["crust"], fg=C["blue"],
                 font=(MONO, 13, "bold")).pack(side="left", padx=16, pady=8)
        self._lbl_count = tk.Label(topbar, text="Agents: 0", bg=C["crust"],
                                    fg=C["green"], font=(MONO, 10))
        self._lbl_count.pack(side="left", padx=12)
        tls_color = C["green"] if self._tls else C["peach"]
        tls_label = "TLS ✓" if self._tls else "⚠ NO TLS"
        tk.Label(topbar, text=tls_label, bg=C["crust"], fg=tls_color,
                 font=(MONO, 10, "bold")).pack(side="left", padx=8)
        self._lbl_clock = tk.Label(topbar, text="", bg=C["crust"], fg=C["overlay0"],
                                    font=(MONO, 10))
        self._lbl_clock.pack(side="right", padx=16)

        # Main split
        pane = ttk.PanedWindow(self.root, orient="horizontal")
        pane.pack(fill="both", expand=True)
        lf = tk.Frame(pane, bg=C["base"], width=300)
        pane.add(lf, weight=1)
        self._build_agent_panel(lf)
        rf = tk.Frame(pane, bg=C["base"])
        pane.add(rf, weight=5)
        self._build_workspace(rf)

        # Status bar
        # BUG FIX #9: show actual host:port from args, not the DEFAULT constants
        sb = tk.Frame(self.root, bg=C["crust"], height=24)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._lbl_status = tk.Label(sb, text="Ready", bg=C["crust"], fg=C["overlay0"],
                                     font=(MONO, 9))
        self._lbl_status.pack(side="left", padx=12)
        tk.Label(sb, text=f"Listening  •  {self._host}:{self._port}",
                 bg=C["crust"], fg=C["teal"], font=(MONO, 9)).pack(
            side="right", padx=12)

    def _build_agent_panel(self, parent):
        tk.Label(parent, text="CONNECTED AGENTS", bg=C["base"], fg=C["blue"],
                 font=(MONO, 10, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Frame(parent, bg=C["surface0"], height=1).pack(fill="x", padx=10)

        cols = ("host", "user", "ip")
        self._atree = ttk.Treeview(parent, columns=cols, show="headings",
                                    selectmode="browse", height=20)
        self._atree.heading("host", text="Hostname")
        self._atree.heading("user", text="User")
        self._atree.heading("ip",   text="IP")
        self._atree.column("host", width=110, minwidth=80)
        self._atree.column("user", width=90,  minwidth=60)
        self._atree.column("ip",   width=100, minwidth=80)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._atree.yview)
        self._atree.configure(yscrollcommand=vsb.set)
        self._atree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=8)
        vsb.pack(side="left", fill="y", pady=8, padx=(2, 8))
        self._atree.bind("<<TreeviewSelect>>", self._on_select)

        bf = tk.Frame(parent, bg=C["base"])
        bf.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bf, text="Sysinfo", command=self._cmd_sysinfo).pack(
            side="left", padx=(0, 4))
        ttk.Button(bf, text="Disconnect", style="Danger.TButton",
                   command=self._disconnect).pack(side="right")

    def _build_workspace(self, parent):
        self._info_strip = tk.Frame(parent, bg=C["mantle"], height=30)
        self._info_strip.pack(fill="x")
        self._info_strip.pack_propagate(False)
        self._lbl_info = tk.Label(self._info_strip, text="  No agent selected",
                                   bg=C["mantle"], fg=C["overlay0"],
                                   font=(MONO, 9))
        self._lbl_info.pack(side="left", padx=10, pady=5)
        self._lbl_admin = tk.Label(self._info_strip, text="", bg=C["mantle"],
                                    fg=C["yellow"], font=(MONO, 9, "bold"))
        self._lbl_admin.pack(side="right", padx=10)

        self._nb = ttk.Notebook(parent)
        self._nb.pack(fill="both", expand=True)
        self._build_terminal_tab()
        self._build_processes_tab()
        self._build_files_tab()
        self._build_sysinfo_tab()

    def _build_terminal_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Terminal  ")
        self._term = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], insertbackground=C["text"],
            font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=10, pady=8,
            selectbackground=C["surface1"])
        self._term.pack(fill="both", expand=True)
        for tag, fg in [
            ("info", C["blue"]), ("success", C["green"]), ("error", C["red"]),
            ("warn", C["peach"]), ("prompt", C["mauve"]), ("output", C["text"]),
            ("dim", C["overlay0"]),
        ]:
            self._term.tag_config(tag, foreground=fg)
        self._term.tag_config("ts", foreground=C["overlay0"], font=(MONO, 9))

        ir = tk.Frame(f, bg=C["crust"])
        ir.pack(fill="x")
        self._lbl_ps = tk.Label(ir, text="PS >", bg=C["crust"], fg=C["mauve"],
                                 font=(MONO, 11, "bold"), padx=10, pady=6)
        self._lbl_ps.pack(side="left")
        self._entry = ttk.Entry(ir, font=(MONO, 11))
        self._entry.pack(side="left", fill="x", expand=True, ipady=3)
        self._entry.bind("<Return>", self._run_shell)
        self._entry.bind("<Up>",     self._hist_up)
        self._entry.bind("<Down>",   self._hist_down)
        ttk.Button(ir, text="Run ▶", style="Accent.TButton",
                   command=self._run_shell).pack(side="left", padx=(6, 10))

    def _build_processes_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Processes  ")
        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="⟳  Refresh", command=self._refresh_procs).pack(
            side="left", padx=(0, 4))
        ttk.Button(bar, text="⛔  Kill", style="Danger.TButton",
                   command=self._kill_proc).pack(side="left", padx=4)
        tk.Label(bar, text="Filter:", bg=C["base"],
                 fg=C["subtext"]).pack(side="right", padx=(4, 0))
        self._pf = ttk.Entry(bar, font=(MONO, 10), width=20)
        self._pf.pack(side="right", padx=4)
        self._pf.bind("<KeyRelease>", self._filter_procs)

        cols = ("pid", "name", "cpu", "ram")
        self._ptree = ttk.Treeview(f, columns=cols, show="headings")
        self._ptree.heading("pid",  text="PID")
        self._ptree.heading("name", text="Process Name")
        self._ptree.heading("cpu",  text="CPU (s)")
        self._ptree.heading("ram",  text="RAM (MB)")
        self._ptree.column("pid",  width=70,  anchor="center")
        self._ptree.column("name", width=220)
        self._ptree.column("cpu",  width=90,  anchor="e")
        self._ptree.column("ram",  width=90,  anchor="e")
        psb = ttk.Scrollbar(f, orient="vertical", command=self._ptree.yview)
        self._ptree.configure(yscrollcommand=psb.set)
        self._ptree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        psb.pack(side="left", fill="y", pady=4, padx=(2, 8))

    def _build_files_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Files  ")
        pb = tk.Frame(f, bg=C["base"])
        pb.pack(fill="x", padx=8, pady=6)
        tk.Label(pb, text="Path:", bg=C["base"],
                 fg=C["subtext"]).pack(side="left", padx=(0, 4))
        self._path_e = ttk.Entry(pb, font=(MONO, 10))
        self._path_e.pack(side="left", fill="x", expand=True)
        self._path_e.bind("<Return>", self._browse)
        ttk.Button(pb, text="Go",   command=self._browse).pack(side="left", padx=4)
        ttk.Button(pb, text="↑ Up", command=self._go_up).pack(side="left", padx=4)

        ab = tk.Frame(f, bg=C["base"])
        ab.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(ab, text="⬇ Download", command=self._download).pack(
            side="left", padx=(0, 4))
        ttk.Button(ab, text="⬆ Upload", command=self._upload).pack(side="left")

        cols = ("name", "type", "size", "modified")
        self._ftree = ttk.Treeview(f, columns=cols, show="headings")
        self._ftree.heading("name",     text="Name")
        self._ftree.heading("type",     text="Type")
        self._ftree.heading("size",     text="Size")
        self._ftree.heading("modified", text="Modified")
        self._ftree.column("name",     width=280)
        self._ftree.column("type",     width=55,  anchor="center")
        self._ftree.column("size",     width=90,  anchor="e")
        self._ftree.column("modified", width=160, anchor="center")
        fsb = ttk.Scrollbar(f, orient="vertical", command=self._ftree.yview)
        self._ftree.configure(yscrollcommand=fsb.set)
        self._ftree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        fsb.pack(side="left", fill="y", pady=4, padx=(2, 8))
        self._ftree.bind("<Double-1>", self._file_dbl)
        self._ftree.tag_configure("dir",  foreground=C["yellow"])
        self._ftree.tag_configure("file", foreground=C["text"])

    def _build_sysinfo_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Sysinfo  ")
        self._sysinfo_tab_frame = f    # BUG FIX #8: store ref, not int index
        ttk.Button(f, text="⟳  Refresh",
                   command=self._refresh_sysinfo).pack(anchor="w", padx=8, pady=8)
        self._si_text = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"],
            font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=16, pady=10)
        self._si_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._si_text.tag_config("key",     foreground=C["blue"],
                                  font=(MONO, 10, "bold"))
        self._si_text.tag_config("val",     foreground=C["text"])
        self._si_text.tag_config("head",    foreground=C["mauve"],
                                  font=(MONO, 11, "bold"))
        self._si_text.tag_config("admin_y", foreground=C["yellow"],
                                  font=(MONO, 10, "bold"))
        self._si_text.tag_config("admin_n", foreground=C["subtext"])

    # ════════════════════════════════════════════════════════════
    #  Agent events — always dispatched onto the main Tk thread
    # ════════════════════════════════════════════════════════════

    def _on_agent_event(self, ev: str, agent: Agent):
        self.root.after(0, self._dispatch_agent_event, ev, agent)

    def _dispatch_agent_event(self, ev: str, agent: Agent):
        if ev == "connect":
            admin_tag = " ★" if (agent.is_admin and agent.os_type == "windows") else ""
            root_tag  = " ⚡" if (agent.is_admin and agent.os_type == "linux") else ""
            priv_tag  = admin_tag or root_tag
            
            iid = self._atree.insert("", "end", values=(
                agent.hostname,
                agent.username.split("\\")[-1].split("/")[-1] + priv_tag,
                agent.ip,
            ))
            self._tree_map[agent.id] = iid
            self._log(
                f"[+] {agent.username}@{agent.hostname}  ({agent.ip})  —  {agent.os}",
                "success")
            if agent.is_admin:
                priv_name = "Root" if agent.os_type == "linux" else "Administrator"
                self._log(f"    {'⚡' if agent.os_type == 'linux' else '★'} Running as {priv_name}", "warn")
        elif ev == "disconnect":
            iid = self._tree_map.pop(agent.id, None)
            if iid:
                try:
                    self._atree.delete(iid)
                except tk.TclError:
                    pass
            if self._sel_id == agent.id:
                self._sel_id = None
                self._lbl_info.config(text="  Agent disconnected", fg=C["red"])
                self._lbl_admin.config(text="")
            self._log(f"[-] Disconnected: {agent.username}@{agent.hostname}", "warn")
        self._lbl_count.config(text=f"Agents: {len(self.server.agents())}")

    def _on_select(self, _=None):
        sel = self._atree.selection()
        if not sel:
            return
        iid = sel[0]
        for aid, tiid in list(self._tree_map.items()):    # list() = safe snapshot
            if tiid == iid:
                self._sel_id = aid
                a = self.server.get(aid)
                if a:
                    ts = a.connected_at.strftime("%H:%M:%S")
                    self._lbl_info.config(
                        fg=C["subtext"],
                        text=f"  {a.username}  @  {a.hostname}  ·  {a.ip}  ·  {a.os}  ·  since {ts}")
                    # Update prompt based on OS
                    if a.os_type == "linux":
                        self._lbl_ps.config(text=f"$ {a.hostname} >")
                        priv_label = "  ⚡ ROOT  " if a.is_admin else ""
                        default_path = "/"
                    else:
                        self._lbl_ps.config(text=f"PS {a.hostname} >")
                        priv_label = "  ★ ADMIN  " if a.is_admin else ""
                        default_path = "C:\\"
                    self._lbl_admin.config(text=priv_label)
                    # Set default file browser path if empty
                    if not self._path_e.get():
                        self._path_e.delete(0, "end")
                        self._path_e.insert(0, default_path)
                break

    def _get_agent(self, warn: bool = True) -> Optional[Agent]:
        if not self._sel_id:
            if warn:
                messagebox.showwarning("No Agent", "Select an agent first.")
            return None
        a = self.server.get(self._sel_id)
        if not a:
            if warn:
                messagebox.showerror("Disconnected", "That agent is no longer connected.")
            return None
        return a

    # ════════════════════════════════════════════════════════════
    #  Terminal
    # ════════════════════════════════════════════════════════════

    def _log(self, text: str, tag: str = "output"):
        self._term.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._term.insert("end", f"[{ts}] ", "ts")
        self._term.insert("end", text + "\n", tag)
        self._term.see("end")
        self._term.config(state="disabled")
        self._lbl_status.config(text=text[:80])

    def _run_shell(self, _=None):
        a = self._get_agent()
        if not a:
            return
        cmd = self._entry.get().strip()
        if not cmd:
            return
        self._cmd_history.append(cmd)
        self._hist_idx = len(self._cmd_history)
        self._entry.delete(0, "end")
        self._log(f"PS > {cmd}", "prompt")
        self.server.audit_cmd(a, "shell", cmd)

        def run():
            mid, _ = a.send_command("shell", cmd)
            resp = a.wait_response(mid, timeout=30)
            if resp:
                out = (resp.get("output") or "").rstrip()
                tag = "output" if resp.get("status") == "ok" else "error"
                self.root.after(0, self._log, out or "(no output)", tag)
            else:
                self.root.after(0, self._log, "Timeout waiting for response", "error")

        threading.Thread(target=run, daemon=True).start()

    def _hist_up(self, _):
        if self._cmd_history and self._hist_idx > 0:
            self._hist_idx -= 1
            self._entry.delete(0, "end")
            self._entry.insert(0, self._cmd_history[self._hist_idx])

    def _hist_down(self, _):
        if self._hist_idx < len(self._cmd_history) - 1:
            self._hist_idx += 1
            self._entry.delete(0, "end")
            self._entry.insert(0, self._cmd_history[self._hist_idx])
        else:
            self._hist_idx = len(self._cmd_history)
            self._entry.delete(0, "end")

    # ════════════════════════════════════════════════════════════
    #  Processes
    # ════════════════════════════════════════════════════════════

    def _refresh_procs(self):
        a = self._get_agent()
        if not a:
            return
        self._log("Fetching process list…", "dim")
        self.server.audit_cmd(a, "ps")

        def run():
            mid, _ = a.send_command("ps")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    procs = json.loads(resp["output"])
                    if isinstance(procs, dict):
                        procs = [procs]
                    self.root.after(0, self._fill_procs, procs)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                self.root.after(0, self._log, "Failed to get process list", "error")

        threading.Thread(target=run, daemon=True).start()

    def _fill_procs(self, procs: List):
        self._proc_cache = procs
        self._render_procs(procs)
        self._log(f"Process list: {len(procs)} entries", "success")

    def _render_procs(self, procs: List):
        for iid in self._ptree.get_children():
            self._ptree.delete(iid)
        for p in procs:
            cpu = p.get("CPU", 0) or 0
            ram = p.get("RAM", 0) or 0
            self._ptree.insert("", "end", values=(
                p.get("Id", ""),
                p.get("ProcessName", ""),
                f"{float(cpu):.1f}",
                f"{float(ram):.1f}",
            ))

    def _filter_procs(self, _=None):
        q = self._pf.get().lower()
        self._render_procs([p for p in self._proc_cache
                            if q in p.get("ProcessName", "").lower()])

    def _kill_proc(self):
        a = self._get_agent()
        if not a:
            return
        sel = self._ptree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a process first.")
            return
        vals = self._ptree.item(sel[0])["values"]
        pid, name = vals[0], vals[1]
        if not messagebox.askyesno("Confirm", f"Kill  '{name}'  (PID {pid})?"):
            return
        self.server.audit_cmd(a, "kill", str(pid))

        def run():
            mid, _ = a.send_command("kill", str(pid))
            resp = a.wait_response(mid, timeout=10)
            if resp:
                tag = "success" if resp.get("status") == "ok" else "error"
                self.root.after(0, self._log, resp.get("output", ""), tag)
                if resp.get("status") == "ok":
                    self.root.after(0, self._refresh_procs)
            else:
                self.root.after(0, self._log, "Kill timed out", "error")

        threading.Thread(target=run, daemon=True).start()

    # ════════════════════════════════════════════════════════════
    #  Files
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def _strip_icon(s: str) -> str:
        """
        BUG FIX #7: Remove the icon prefix correctly.
        The original code used lstrip("📁📄 ") which strips any INDIVIDUAL
        CHARACTER in the given set from the left — not the literal prefix string.
        This would corrupt filenames beginning with a space.
        We now check for the exact prefix string before removing it.
        """
        for prefix in ("📁  ", "📄  "):
            if s.startswith(prefix):
                return s[len(prefix):]
        return s

    @staticmethod
    def _win_parent(path: str) -> str:
        """
        BUG FIX #6: Windows-path-aware parent directory.
        os.path.dirname uses the *server's* separator. On Linux the backslash
        is not a separator, so dirname("C:\\Users\\foo") returns "" instead of
        "C:\\Users".  We handle Windows paths explicitly here.
        """
        p = path.rstrip("\\")
        if not p:
            return path
        idx = p.rfind("\\")
        if idx < 0:
            return path                  # e.g. "C:" — already at drive root
        if idx == 2 and len(p) > 2 and p[1] == ":":
            return p[:2] + "\\"          # "C:\Users" → "C:\"
        return p[:idx] if idx > 0 else path

    def _browse(self, _=None):
        a = self._get_agent()
        if not a:
            return
        path = self._path_e.get().strip()

        def run():
            mid, _ = a.send_command("ls", path)
            resp = a.wait_response(mid, timeout=15)
            if resp and resp.get("status") == "ok":
                try:
                    items = json.loads(resp["output"])
                    if isinstance(items, dict):
                        items = [items]
                    self.root.after(0, self._fill_files, items, path)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                err = (resp or {}).get("output", "Timeout")
                self.root.after(0, self._log, f"Browse error: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _fill_files(self, items: List, path: str):
        for iid in self._ftree.get_children():
            self._ftree.delete(iid)
        dirs  = sorted([i for i in items if i.get("Type") == "dir"],
                        key=lambda x: x.get("Name", "").lower())
        files = sorted([i for i in items if i.get("Type") != "dir"],
                        key=lambda x: x.get("Name", "").lower())
        for it in dirs:
            self._ftree.insert("", "end",
                                values=("📁  " + it["Name"], "DIR", "",
                                        str(it.get("LastWriteTime", ""))),
                                tags=("dir",))
        for it in files:
            self._ftree.insert("", "end",
                                values=("📄  " + it["Name"], "FILE",
                                        self._fmt_sz(it.get("Length") or 0),
                                        str(it.get("LastWriteTime", ""))),
                                tags=("file",))
        self._path_e.delete(0, "end")
        self._path_e.insert(0, path)

    @staticmethod
    def _fmt_sz(n) -> str:
        try:
            n = int(n)
        except (TypeError, ValueError):
            return ""
        if n < 1024:     return f"{n} B"
        if n < 1024**2:  return f"{n/1024:.1f} KB"
        if n < 1024**3:  return f"{n/1024**2:.1f} MB"
        return f"{n/1024**3:.2f} GB"

    def _file_dbl(self, _):
        sel = self._ftree.selection()
        if not sel:
            return
        vals  = self._ftree.item(sel[0])["values"]
        name  = self._strip_icon(str(vals[0]))
        ftype = vals[1]
        if ftype == "DIR":
            a = self._get_agent(warn=False)
            cur = self._path_e.get()
            
            if a and a.os_type == "linux":
                # Linux: use forward slashes
                cur = cur.rstrip("/")
                new_path = f"{cur}/{name}" if cur != "/" else f"/{name}"
            else:
                # Windows: use backslashes
                cur = cur.rstrip("\\")
                new_path = cur + "\\" + name
            
            self._path_e.delete(0, "end")
            self._path_e.insert(0, new_path)
            self._browse()

    def _go_up(self):
        a = self._get_agent(warn=False)
        current = self._path_e.get()
        
        if a and a.os_type == "linux":
            # Linux: use forward slashes
            parent = current.rstrip("/")
            if "/" in parent:
                parent = parent.rsplit("/", 1)[0]
                if not parent:
                    parent = "/"
            else:
                parent = "/"
        else:
            # Windows: use backslashes with _win_parent
            parent = self._win_parent(current)
        
        self._path_e.delete(0, "end")
        self._path_e.insert(0, parent)
        self._browse()

    def _download(self):
        a = self._get_agent()
        if not a:
            return
        sel = self._ftree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a file to download.")
            return
        name = self._strip_icon(str(self._ftree.item(sel[0])["values"][0]))
        
        # Construct remote path with correct separator
        cur = self._path_e.get()
        if a.os_type == "linux":
            cur = cur.rstrip("/")
            remote = f"{cur}/{name}" if cur != "/" else f"/{name}"
        else:
            remote = cur.rstrip("\\") + "\\" + name
        
        save = filedialog.asksaveasfilename(initialfile=name)
        if not save:
            return
        self.server.audit_cmd(a, "download", remote)

        def run():
            self.root.after(0, self._log, f"Downloading  {remote} …", "info")
            mid, _ = a.send_command("download", remote)
            resp = a.wait_response(mid, timeout=120)
            if resp and resp.get("status") == "ok":
                try:
                    data = base64.b64decode(resp["output"])
                    with open(save, "wb") as fh:
                        fh.write(data)
                    self.root.after(0, self._log,
                                   f"Saved {len(data):,} bytes  →  {save}", "success")
                except Exception as e:
                    self.root.after(0, self._log, f"Save error: {e}", "error")
            else:
                err = (resp or {}).get("output", "Timeout")
                self.root.after(0, self._log, f"Download failed: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _upload(self):
        a = self._get_agent()
        if not a:
            return
        local = filedialog.askopenfilename()
        if not local:
            return
        fname = os.path.basename(local)
        
        # Construct remote path with correct separator
        cur = self._path_e.get()
        if a.os_type == "linux":
            cur = cur.rstrip("/")
            remote = f"{cur}/{fname}" if cur != "/" else f"/{fname}"
        else:
            remote = cur.rstrip("\\") + "\\" + fname
        
        self.server.audit_cmd(a, "upload", remote)

        def run():
            self.root.after(0, self._log, f"Uploading  {fname}  →  {remote} …", "info")
            try:
                with open(local, "rb") as fh:
                    b64 = base64.b64encode(fh.read()).decode()
                mid, _ = a.send_command("upload", path=remote, data=b64)
                resp = a.wait_response(mid, timeout=120)
                if resp and resp.get("status") == "ok":
                    self.root.after(0, self._log, resp.get("output", "Uploaded"), "success")
                    self.root.after(0, self._browse)
                else:
                    err = (resp or {}).get("output", "Timeout")
                    self.root.after(0, self._log, f"Upload failed: {err}", "error")
            except Exception as e:
                self.root.after(0, self._log, f"Upload error: {e}", "error")

        threading.Thread(target=run, daemon=True).start()

    # ════════════════════════════════════════════════════════════
    #  Sysinfo
    # ════════════════════════════════════════════════════════════

    def _cmd_sysinfo(self):
        self._refresh_sysinfo()
        # BUG FIX #8: select by frame reference, not by hardcoded int index
        if self._sysinfo_tab_frame:
            self._nb.select(self._sysinfo_tab_frame)

    def _refresh_sysinfo(self):
        a = self._get_agent()
        if not a:
            return
        self.server.audit_cmd(a, "sysinfo")

        def run():
            mid, _ = a.send_command("sysinfo")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    info = json.loads(resp["output"])
                    self.root.after(0, self._render_sysinfo, info)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                self.root.after(0, self._log, "Sysinfo request failed", "error")

        threading.Thread(target=run, daemon=True).start()

    def _render_sysinfo(self, info: dict):
        t = self._si_text
        t.config(state="normal")
        t.delete("1.0", "end")

        def row(label: str, value: str, val_tag: str = "val"):
            t.insert("end", f"  {label:<22}", "key")
            t.insert("end", f"{value}\n", val_tag)

        t.insert("end", "\n")
        t.insert("end", "  SYSTEM INFORMATION\n", "head")
        t.insert("end", "  " + "─" * 50 + "\n\n")
        row("Hostname",     info.get("hostname", "N/A"))
        row("Username",     info.get("username", "N/A"))
        row("OS",           info.get("os",       "N/A"))
        row("Architecture", info.get("arch",     "N/A"))
        row("RAM (GB)",     str(info.get("ram_gb", "N/A")))
        row("Uptime",       info.get("uptime",   "N/A"))
        
        # Show appropriate version label based on what's present
        if "python_ver" in info:
            row("Python",   info.get("python_ver", "N/A"))
        elif "ps_ver" in info:
            row("PowerShell", info.get("ps_ver", "N/A"))
        
        row("Working Dir",  info.get("cwd",      "N/A"))
        row("Local IP",     info.get("local_ip", "N/A"))
        
        t.insert("end", f"\n  {'Privileges':<22}", "key")
        # Check both is_root (Linux) and is_admin (Windows)
        if info.get("is_root") or info.get("is_admin"):
            label = "⚡  Root" if info.get("is_root") else "★  Administrator"
            t.insert("end", f"{label}\n", "admin_y")
        else:
            t.insert("end", "Standard User\n", "admin_n")
        
        t.insert("end", "\n")
        t.config(state="disabled")

    # ════════════════════════════════════════════════════════════
    #  Misc
    # ════════════════════════════════════════════════════════════

    def _disconnect(self):
        a = self._get_agent()
        if not a:
            return
        if messagebox.askyesno("Disconnect", f"Close connection to {a.hostname}?"):
            AUDIT.info("MANUAL_DISCONNECT  user=%s  host=%s", a.username, a.hostname)
            try:
                a.conn.close()
            except Exception:
                pass

    def _start_clock(self):
        def tick():
            self._lbl_clock.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
            self.root.after(1000, tick)
        tick()


# ════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Secure RAT Server")
    p.add_argument("--host",   default=DEFAULT_HOST,
                   help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port",   type=int, default=DEFAULT_PORT,
                   help="TCP port (default: 4444)")
    p.add_argument("--psk",    default=None,
                   help="Pre-shared key for agent auth (auto-generated if omitted)")
    p.add_argument("--cert",   default=CERT_FILE,
                   help=f"TLS certificate PEM (default: {CERT_FILE})")
    p.add_argument("--key",    default=KEY_FILE,
                   help=f"TLS private key PEM (default: {KEY_FILE})")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable TLS — NOT recommended for production")
    p.add_argument("--allow",  action="append", metavar="CIDR",
                   help="Restrict incoming connections to CIDR (repeatable)")
    args = p.parse_args()

    psk = ensure_psk(PSK_FILE, args.psk)
    print(f"\n{'='*60}")
    print(f"  PSK  →  {psk}")
    print(f"  Set $PSK = \"{psk}\" in agent.ps1")

    tls_context: Optional[ssl.SSLContext] = None
    fingerprint: Optional[str] = None

    if not args.no_tls:
        fingerprint = ensure_cert(args.cert, args.key)
        if fingerprint:
            with open(FPRINT_FILE, "w") as f:
                f.write(fingerprint)
            print(f"\n  Cert fingerprint  →  {fingerprint}")
            print(f"  Set $CertThumbprint = \"{fingerprint}\" in agent.ps1")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(args.cert, args.key)
            tls_context = ctx
        else:
            print("\n  WARNING: TLS unavailable — traffic will be unencrypted")
    else:
        print("\n  WARNING: TLS disabled — traffic will be unencrypted")
    print(f"{'='*60}\n")

    allow_nets: List[IPv4Network] = []
    if args.allow:
        for cidr in args.allow:
            try:
                allow_nets.append(ip_network(cidr, strict=False))
                print(f"[*] IP restriction: {cidr}")
            except ValueError as e:
                print(f"[!] Invalid CIDR '{cidr}': {e}")

    AUDIT.info("SERVER_START  host=%s  port=%d  tls=%s  allow=%s",
               args.host, args.port, tls_context is not None,
               [str(n) for n in allow_nets] or "any")

    root = tk.Tk()
    root.tk_setPalette(background=C["base"], foreground=C["text"])
    App(root, args.host, args.port, psk, tls_context, fingerprint, allow_nets)
    root.mainloop()


if __name__ == "__main__":
    main()
