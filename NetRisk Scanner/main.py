"""
main.py — Core Logic for Intelligent IPv4 Port Scanner
=======================================================
Contains:
  - Constants (service map, risk weights, thresholds, GUI colours)
  - Pure helper functions (validate_ipv4, detect_service, get_risk_weight,
    calculate_risk_level, scan_port)
  - Banner grabbing  (grab_banner, identify_from_banner)
  - Reachability check (is_host_reachable)
  - Export helpers (build_export_data, export_json)
  - PortScannerEngine (threaded scan loop with stop support)

Import this module from gui.py and testcode.py.

DISCLAIMER: Only scan hosts you own or have explicit permission to scan.
"""

import json
import re
import socket
import threading
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants & Lookup Tables
# ---------------------------------------------------------------------------

# Maps well-known port numbers to human-readable service names.
# Extended from 12 to 40+ ports so the tool covers a much wider surface.
# For ports NOT in this map, detect_service() falls back to the OS-level
# socket.getservbyport() database which covers hundreds of additional ports.
SERVICE_MAP: dict[int, str] = {
    # ── Remote access ──────────────────────────────────────────────────
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    # ── Mail ───────────────────────────────────────────────────────────
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    993:   "IMAPS",
    995:   "POP3S",
    # ── Web ────────────────────────────────────────────────────────────
    80:    "HTTP",
    443:   "HTTPS",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    # ── DNS / network infrastructure ───────────────────────────────────
    53:    "DNS",
    67:    "DHCP",
    69:    "TFTP",
    123:   "NTP",
    161:   "SNMP",
    # ── File sharing / Windows networking ──────────────────────────────
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    445:   "SMB",
    2049:  "NFS",
    # ── Databases ──────────────────────────────────────────────────────
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    9200:  "Elasticsearch",
    27017: "MongoDB",
    # ── Other common services ──────────────────────────────────────────
    111:   "RPC",
    135:   "MSRPC",
    389:   "LDAP",
    636:   "LDAPS",
    514:   "Syslog",
    631:   "IPP",
    194:   "IRC",
    6667:  "IRC-Alt",
}

# ---------------------------------------------------------------------------
# Risk Weights  (CVE-justified — see inline notes for each rating)
# ---------------------------------------------------------------------------
#
# Weights reflect real-world exploitation history and CVSS base scores.
# Higher weight = greater risk of system compromise or data breach when
# that port is found open on a network host.
#
#  5 — CRITICAL
#      Telnet (23):
#        Transmits ALL data including credentials as plain text.
#        Zero encryption.  Any network observer captures passwords trivially.
#        Deprecated by SSH in the early 2000s.  CVSS equivalent: 9.8.
#
#  4 — HIGH
#      RDP (3389):
#        BlueKeep  CVE-2019-0708  unauthenticated RCE,  CVSS 9.8.
#        DejaBlue  CVE-2019-1181  wormable RCE,          CVSS 9.8.
#        Exposed RDP is the #1 ransomware initial-access vector worldwide.
#
#      SMB (445):
#        EternalBlue CVE-2017-0144  CVSS 8.1  — exploited by WannaCry
#        and NotPetya, causing billions in damages globally.
#        PrintNightmare CVE-2021-1675  CVSS 8.8  — spooler privilege
#        escalation still found on unpatched Windows systems.
#
#      MySQL (3306) / MSSQL (1433) / Oracle-DB (1521) / PostgreSQL (5432):
#        Direct database port exposure.  No application-layer firewall
#        between attacker and data.  Enables brute-force and exfiltration.
#
#      Redis (6379):
#        No authentication by default in older versions.
#        CVE-2022-0543  CVSS 10.0 — unauthenticated RCE via Lua sandbox
#        escape.  Arbitrary file writes allow SSH key injection.
#
#      MongoDB (27017):
#        Unauthenticated by default before v3.0.  Hundreds of thousands
#        of instances were wiped and held for ransom in 2017.
#
#      VNC (5900):
#        Full graphical desktop if compromised.  Often weak/no passwords.
#        CVE-2019-15681  CVSS 9.8  — memory disclosure leading to RCE.
#
#  3 — MEDIUM-HIGH
#      FTP (21):
#        Plaintext credentials like Telnet, lower risk because less used
#        for interactive sessions today.  Anonymous FTP misconfigs common.
#
#      TFTP (69):
#        No authentication.  Anyone can read/write files.  Exploited for
#        config theft on routers and switches.
#
#      SNMP (161):
#        Default community strings ("public"/"private") allow full device
#        info disclosure and sometimes write access.
#        CVE-2017-6736 Cisco IOS  CVSS 9.8.
#
#      NetBIOS (137-139):
#        Exposes Windows hostnames, user lists, and shares without auth.
#        Foundation for lateral movement and enumeration attacks.
#
#  2 — MEDIUM
#      SSH (22):
#        Encrypted, but exposed SSH attracts brute-force and credential-
#        stuffing.  Lower risk than Telnet — credentials protected in transit.
#
#      Mail ports (25, 465, 587, 110, 143, 993, 995):
#        Risk is open relay abuse and credential exposure, not direct RCE.
#
#      LDAP/LDAPS (389, 636):
#        Anonymous bind can expose Active Directory user/group enumeration.
#
#      RPC/MSRPC (111, 135):
#        Used by historical Windows worms (Blaster, Sasser).
#        Lower risk on modern patched systems.
#
#  1 — LOW
#      HTTP/HTTPS (80, 443, 8080, 8443, 8888):
#        Expected to be public-facing.  Risk is in the web application,
#        not the port exposure itself.
#
#      DNS (53):  Expected public service.  Risk is DNS amplification for
#        DDoS — not a direct host compromise risk.
#
#      NTP, DHCP, IPP, Syslog, NFS — informational / low direct risk.
#
RISK_WEIGHTS: dict[str, int] = {
    # Critical
    "Telnet":           5,
    # High
    "RDP":              4,
    "SMB":              4,
    "MySQL":            4,
    "MSSQL":            4,
    "Oracle-DB":        4,
    "PostgreSQL":       4,
    "Redis":            4,
    "MongoDB":          4,
    "VNC":              4,
    # Medium-High
    "FTP":              3,
    "TFTP":             3,
    "SNMP":             3,
    "NetBIOS-NS":       3,
    "NetBIOS-DGM":      3,
    "NetBIOS-SSN":      3,
    # Medium
    "SSH":              2,
    "SMTP":             2,
    "SMTPS":            2,
    "SMTP-Submission":  2,
    "POP3":             2,
    "POP3S":            2,
    "IMAP":             2,
    "IMAPS":            2,
    "LDAP":             2,
    "LDAPS":            2,
    "RPC":              2,
    "MSRPC":            2,
    "IRC":              2,
    "IRC-Alt":          2,
    # Low
    "HTTP":             1,
    "HTTPS":            1,
    "HTTP-Alt":         1,
    "HTTPS-Alt":        1,
    "HTTP-Dev":         1,
    "DNS":              1,
    "DHCP":             1,
    "NTP":              1,
    "IPP":              1,
    "Syslog":           1,
    "NFS":              1,
    "Elasticsearch":    1,
    "Unknown Service":  1,
}

# Score thresholds that map total risk score to a risk label.
RISK_LOW_MAX    = 5    # total score ≤ 5  → Low
RISK_MEDIUM_MAX = 12   # total score ≤ 12 → Medium  (else High)

# ---------------------------------------------------------------------------
# GUI Colour Constants
# (Defined here so gui.py imports them from one place.)
# ---------------------------------------------------------------------------

COLOR_LOW    = "#27ae60"   # green  — Low risk
COLOR_MEDIUM = "#f39c12"   # amber  — Medium risk
COLOR_HIGH   = "#e74c3c"   # red    — High risk
COLOR_BG     = "#1e1e2e"   # dark background
COLOR_FG     = "#cdd6f4"   # light foreground text
COLOR_ACCENT = "#89b4fa"   # blue accent (headings, title)
COLOR_ROW_A  = "#313244"   # alternate table row
COLOR_ROW_B  = "#1e1e2e"   # default table row background

# ---------------------------------------------------------------------------
# Scan Engine Parameters
# ---------------------------------------------------------------------------

MAX_THREADS    = 100   # maximum concurrent probe threads
SOCKET_TIMEOUT = 0.5   # seconds per TCP connection attempt (fast)
BANNER_TIMEOUT = 2.0   # seconds to wait for banner data (needs to be longer)

# ---------------------------------------------------------------------------
# Banner Grabbing
# ---------------------------------------------------------------------------

# Regex patterns for identifying a service from its raw banner text.
# Ordered most-specific → least-specific so earlier matches win.
BANNER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-\d",              re.I), "SSH"),
    (re.compile(r"220.*ftp|530 login",  re.I), "FTP"),
    (re.compile(r"220.*smtp|250.*smtp", re.I), "SMTP"),
    (re.compile(r"HTTP/\d",             re.I), "HTTP"),
    (re.compile(r"\+OK",                re.I), "POP3"),
    (re.compile(r"\* OK.*IMAP",         re.I), "IMAP"),
    (re.compile(r"RFB \d+\.\d+",        re.I), "VNC"),
    (re.compile(r"mysql|mariadb",       re.I), "MySQL"),
    (re.compile(r"redis",               re.I), "Redis"),
    (re.compile(r"mongodb",             re.I), "MongoDB"),
    (re.compile(r"postgresql|pg_hba",   re.I), "PostgreSQL"),
]

# Services that only respond after the client speaks first.
# Key = service name from SERVICE_MAP, value = bytes to send.
SERVICE_PROBES: dict[str, bytes] = {
    "HTTP":      b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "HTTP-Alt":  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "HTTPS-Alt": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "HTTP-Dev":  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}


def identify_from_banner(banner: str) -> str:
    """
    Match *banner* text against BANNER_PATTERNS.

    Returns the matched service name string, or '' if no pattern matches.
    An empty return means the caller should keep the port-number-derived name.
    """
    for pattern, name in BANNER_PATTERNS:
        if pattern.search(banner):
            return name
    return ""


def grab_banner(host: str, port: int, service_hint: str = "",
                timeout: float = BANNER_TIMEOUT) -> str:
    """
    Connect to an already-open *host*:*port* and read its service banner.

    Strategy
    --------
    1. Open a TCP connection to host:port.
    2. If *service_hint* is in SERVICE_PROBES, send the probe bytes
       (HTTP and some databases wait for the client to speak first).
    3. Read up to 1 KB of response data.
    4. Return the first non-empty line, stripped of control characters,
       truncated to 120 characters.

    Returns '' on any socket error, timeout, or if nothing is received.

    Parameters
    ----------
    host         : IPv4 address (port already confirmed open by scan_port).
    port         : Port to grab the banner from.
    service_hint : Name from detect_service() — selects the right probe.
    timeout      : Socket read timeout (default BANNER_TIMEOUT = 2.0 s).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Some services only speak after receiving a request.
            probe = SERVICE_PROBES.get(service_hint)
            if probe:
                s.sendall(probe)

            raw = s.recv(1024).decode("utf-8", errors="ignore")
            if not raw.strip():
                return ""

            # Keep the first meaningful line; strip control characters.
            first_line = raw.strip().splitlines()[0]
            clean = re.sub(r"[\x00-\x1f\x7f]", " ", first_line).strip()
            return clean[:120]

    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Reachability Check
# ---------------------------------------------------------------------------

def is_host_reachable(host: str, timeout: float = 2.0) -> bool:
    """
    Quick check to see if *host* is up before starting a full port scan.

    Probes a handful of ports that are commonly open on live hosts.
    If any one responds with a successful TCP connection the host is
    considered reachable and True is returned immediately.

    This is not definitive — a host with none of the probe ports open
    will return False even if it is alive.  The result is used only to
    show a warning dialog, never to silently block a scan.

    Parameters
    ----------
    host    : IPv4 address (already validated).
    timeout : Seconds to wait per probe port (default 2.0).
    """
    PROBE_PORTS = (80, 443, 22, 445, 8080)
    for port in PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return True
        except (socket.error, OSError):
            continue
    return False


# ---------------------------------------------------------------------------
# Core Logic Functions
# ---------------------------------------------------------------------------

def validate_ipv4(address: str) -> bool:
    """
    Return True if *address* is a syntactically valid IPv4 string.

    Checks four dot-separated numeric groups each in range 0–255.
    """
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, address):
        return False
    parts = address.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def detect_service(port: int) -> str:
    """
    Return the service name for *port* using a three-layer approach:

    1. SERVICE_MAP  — our curated 40+ port table (clean names, risk weights
                      are guaranteed to exist in RISK_WEIGHTS).
    2. socket.getservbyport() — OS services database, covers hundreds more
                      ports automatically without any code changes.
    3. 'Unknown Service' — graceful fallback.
    """
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "Unknown Service"


def get_risk_weight(service: str) -> int:
    """
    Return the integer risk weight for *service*.
    Defaults to 1 for any name not in RISK_WEIGHTS.
    """
    return RISK_WEIGHTS.get(service, 1)


def calculate_risk_level(total_score: int) -> tuple[str, str]:
    """
    Map *total_score* to a (label, emoji) risk level pair.

      score ≤ RISK_LOW_MAX     → ('Low',    '🟢')
      score ≤ RISK_MEDIUM_MAX  → ('Medium', '🟡')
      score >  RISK_MEDIUM_MAX → ('High',   '🔴')
    """
    if total_score <= RISK_LOW_MAX:
        return ("Low", "🟢")
    elif total_score <= RISK_MEDIUM_MAX:
        return ("Medium", "🟡")
    else:
        return ("High", "🔴")


def scan_port(host: str, port: int, timeout: float = SOCKET_TIMEOUT) -> bool:
    """
    Attempt a TCP connect to *host*:*port*.

    Returns True if open, False if closed/filtered/unreachable.
    Socket is always closed after the attempt.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except (socket.error, OSError):
        return False


# ---------------------------------------------------------------------------
# Export Helpers
# ---------------------------------------------------------------------------

def build_export_data(
    target_ip:  str,
    start_port: int,
    end_port:   int,
    results:    list[dict],
    duration_s: float = 0.0,
) -> dict:
    """
    Build a structured export dictionary from scan *results*.

    Parameters
    ----------
    target_ip  : Scanned IPv4 address.
    start_port : Start of the scanned port range.
    end_port   : End of the scanned port range.
    results    : List of dicts with keys 'port', 'status', 'service',
                 and optionally 'banner'.
    duration_s : Elapsed scan time in seconds.
    """
    open_ports  = [r for r in results if r["status"] == "Open"]
    total_score = sum(get_risk_weight(r["service"]) for r in open_ports)
    risk_label, risk_emoji = calculate_risk_level(total_score)
    highest = max(open_ports,
                  key=lambda r: get_risk_weight(r["service"]),
                  default=None)

    return {
        "tool":                 "Intelligent IPv4 Port Scanner",
        "timestamp":            datetime.now().isoformat(timespec="seconds"),
        "target_ip":            target_ip,
        "start_port":           start_port,
        "end_port":             end_port,
        "duration_seconds":     round(duration_s, 1),
        "total_risk_score":     total_score,
        "risk_level":           f"{risk_emoji} {risk_label}",
        "highest_risk_service": highest["service"] if highest else "None",
        "summary": {
            "ports_scanned": len(results),
            "open_count":    len(open_ports),
            "closed_count":  len(results) - len(open_ports),
            "risk_level":    f"{risk_emoji} {risk_label}",
            "risk_score":    total_score,
        },
        "open_ports": [
            {
                "port":        r["port"],
                "service":     r["service"],
                "banner":      r.get("banner", ""),
                "risk_weight": get_risk_weight(r["service"]),
            }
            for r in open_ports
        ],
        "all_results": results,
    }


def export_json(data: dict, filepath: str) -> None:
    """Write *data* as pretty-printed JSON to *filepath*."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------

class PortScannerEngine:
    """
    Threaded port-scan loop with banner grabbing and cooperative stop support.

    on_result callback signature changed to:
        on_result(port: int, is_open: bool, service: str, banner: str)

    All other behaviour (semaphore, stop event, progress callbacks) is
    identical to the previous version.
    """

    def __init__(
        self,
        host:        str,
        start_port:  int,
        end_port:    int,
        on_result:   callable,   # (port, is_open, service, banner) → None
        on_progress: callable,   # (current, total) → None
        on_complete: callable,   # () → None
    ) -> None:
        self.host        = host
        self.start_port  = start_port
        self.end_port    = end_port
        self.on_result   = on_result
        self.on_progress = on_progress
        self.on_complete = on_complete
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal all threads to exit at their next checkpoint."""
        self._stop_event.set()

    def run(self) -> None:
        """
        Scan all ports in [start_port, end_port] concurrently.

        For each open port:
          1. detect_service()       — port-number lookup (3 layers)
          2. grab_banner()          — active banner read
          3. identify_from_banner() — override service name if banner
                                      reveals something different

        All results are passed to on_result(); on_complete() fires when done.
        """
        ports     = list(range(self.start_port, self.end_port + 1))
        total     = len(ports)
        semaphore = threading.Semaphore(MAX_THREADS)
        threads: list[threading.Thread] = []
        completed = [0]
        lock      = threading.Lock()

        def probe(port: int) -> None:
            if self._stop_event.is_set():
                semaphore.release()
                return

            is_open = scan_port(self.host, port)

            if is_open:
                # Step 1 — name by port number (3-layer lookup)
                service = detect_service(port)
                # Step 2 — actively read the banner
                banner  = grab_banner(self.host, port, service_hint=service)
                # Step 3 — if banner contradicts port-number guess, prefer banner
                if banner:
                    detected = identify_from_banner(banner)
                    if detected and detected != service:
                        service = detected
            else:
                service = "-"
                banner  = ""

            self.on_result(port, is_open, service, banner)

            with lock:
                completed[0] += 1
                self.on_progress(completed[0], total)

            semaphore.release()

        for port in ports:
            if self._stop_event.is_set():
                break
            semaphore.acquire()
            t = threading.Thread(target=probe, args=(port,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.on_complete()