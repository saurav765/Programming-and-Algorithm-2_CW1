
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from main import (
    # Colour constants
    COLOR_ACCENT, COLOR_BG, COLOR_FG,
    COLOR_HIGH, COLOR_LOW, COLOR_MEDIUM, COLOR_ROW_B,
    # Core functions
    build_export_data, calculate_risk_level, detect_service,
    export_json, get_risk_weight, validate_ipv4,
    is_host_reachable,
    # Engine
    PortScannerEngine,
)

# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

class PortScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetRisk Scanner")
        self.configure(bg=COLOR_BG)
        self.resizable(True, True)
        self.minsize(900, 580)

        # ── Runtime state ──────────────────────────────────────────────
        self._engine: PortScannerEngine | None = None
        self._scan_thread: threading.Thread | None = None
        self._results: list[dict] = []
        self._pending_updates: list = []
        self._lock = threading.Lock()

        # Sorting state
        self._sort_status_asc: bool = True
        self._sort_risk_asc:   bool = False

        # Elapsed time tracking
        self._scan_start_time: float = 0.0

        self._build_ui()
        self._poll_updates()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Create and pack every widget."""

        # ── 1. Title bar ───────────────────────────────────────────────
        title_frame = tk.Frame(self, bg=COLOR_BG)
        title_frame.pack(fill=tk.X, padx=12, pady=(12, 4))

        tk.Label(
            title_frame,
            text="🔍  NetRisk Scanner",
            font=("Helvetica", 18, "bold"),
            bg=COLOR_BG, fg=COLOR_ACCENT,
        ).pack(side=tk.LEFT)

        tk.Label(
            title_frame,
            text="Educational tool — only scan hosts you own or have permission to test",
            font=("Helvetica", 9),
            bg=COLOR_BG, fg="#6c7086",
        ).pack(side=tk.LEFT, padx=14)

        # ── 2. Scan-parameter form ─────────────────────────────────────
        form = tk.LabelFrame(
            self, text=" Scan Parameters ",
            bg=COLOR_BG, fg=COLOR_FG,
            font=("Helvetica", 10, "bold"),
            bd=1, relief=tk.GROOVE,
        )
        form.pack(fill=tk.X, padx=12, pady=6)

        def labeled_entry(parent, label, default, width=18):
            row = tk.Frame(parent, bg=COLOR_BG)
            row.pack(side=tk.LEFT, padx=10, pady=6)
            tk.Label(row, text=label, bg=COLOR_BG, fg=COLOR_FG,
                     font=("Helvetica", 10)).pack(anchor=tk.W)
            var = tk.StringVar(value=default)
            tk.Entry(
                row, textvariable=var, width=width,
                bg="#313244", fg=COLOR_FG,
                insertbackground=COLOR_FG,
                relief=tk.FLAT, font=("Courier", 11),
            ).pack()
            return var

        self.ip_var    = labeled_entry(form, "Target IPv4 Address", "127.0.0.1", 20)
        self.start_var = labeled_entry(form, "Start Port",          "1",          8)
        self.end_var   = labeled_entry(form, "End Port",            "1024",       8)

        # ── 3. Action buttons ──────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X, padx=12, pady=4)

        def make_btn(parent, text, cmd, color="#404040"):
            return tk.Button(
                parent, text=text, command=cmd,
                bg=color, fg="white",
                activebackground=color, activeforeground="white",
                font=("Helvetica", 10, "bold"),
                relief=tk.FLAT, padx=14, pady=6, cursor="hand2",
            )

        self.btn_start  = make_btn(btn_frame, "▶  Start Scan",   self._start_scan,  "#1e6fa5")
        self.btn_stop   = make_btn(btn_frame, "■  Stop Scan",    self._stop_scan,   "#a5341e")
        self.btn_export = make_btn(btn_frame, "💾  Export JSON",  self._export,      "#2d6a4f")
        # Risk Info button — always enabled so user can read it any time
        self.btn_info   = make_btn(btn_frame, "ℹ  Risk Info",    self._show_risk_info, "#5c4a8a")

        self.btn_start.pack(side=tk.LEFT, padx=(0, 6))
        self.btn_stop.pack(side=tk.LEFT, padx=6)
        self.btn_export.pack(side=tk.LEFT, padx=6)
        self.btn_info.pack(side=tk.LEFT, padx=6)

        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.DISABLED)

        # ── 4. Progress indicator ──────────────────────────────────────
        prog_frame = tk.Frame(self, bg=COLOR_BG)
        prog_frame.pack(fill=tk.X, padx=12, pady=2)

        self.progress_label = tk.Label(
            prog_frame, text="Ready.",
            bg=COLOR_BG, fg="#6c7086",
            font=("Helvetica", 9), anchor=tk.W,
        )
        self.progress_label.pack(fill=tk.X)

        self.progress_bar = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress_bar.pack(fill=tk.X, pady=2)

        # ── 5. Sort buttons ────────────────────────────────────────────
        sort_frame = tk.Frame(self, bg=COLOR_BG)
        sort_frame.pack(fill=tk.X, padx=12, pady=(2, 0))

        tk.Label(
            sort_frame, text="Sort results:",
            bg=COLOR_BG, fg="#6c7086", font=("Helvetica", 9),
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.btn_sort_status = tk.Button(
            sort_frame, text="⇅  Sort by Status",
            command=self._sort_by_status,
            bg="#404040", fg="white",
            activebackground="#505050", activeforeground="white",
            font=("Helvetica", 9, "bold"),
            relief=tk.FLAT, padx=10, pady=3, cursor="hand2",
            state=tk.DISABLED,
        )
        self.btn_sort_status.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_sort_risk = tk.Button(
            sort_frame, text="⇅  Sort by Risk",
            command=self._sort_by_risk,
            bg="#404040", fg="white",
            activebackground="#505050", activeforeground="white",
            font=("Helvetica", 9, "bold"),
            relief=tk.FLAT, padx=10, pady=3, cursor="hand2",
            state=tk.DISABLED,
        )
        self.btn_sort_risk.pack(side=tk.LEFT)

        # ── 6. Results Treeview ────────────────────────────────────────
        table_frame = tk.Frame(self, bg=COLOR_BG)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # Banner column added — shows the raw service fingerprint grabbed
        # from the live port, confirming (or correcting) the service name.
        cols = ("Port", "Status", "Service", "Banner", "Risk Level")
        self.tree = ttk.Treeview(
            table_frame, columns=cols,
            show="headings", selectmode="browse",
        )
        col_widths = {
            "Port":       70,
            "Status":     80,
            "Service":    130,
            "Banner":     260,   # wider so banners are readable
            "Risk Level": 120,
        }
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=col_widths[c], anchor=tk.CENTER)

        # Banner column is left-aligned so text reads naturally
        self.tree.column("Banner", anchor=tk.W)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL,
                                  command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=COLOR_ROW_B, foreground=COLOR_FG,
            fieldbackground=COLOR_ROW_B, rowheight=24,
        )
        style.configure(
            "Treeview.Heading",
            background="#313244", foreground=COLOR_ACCENT,
            font=("Helvetica", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#585b70")])

        self.tree.tag_configure("open",   background="#1a3a2a", foreground="#a6e3a1")
        self.tree.tag_configure("closed", background=COLOR_ROW_B, foreground="#585b70")
        self.tree.tag_configure("high",   foreground=COLOR_HIGH)
        self.tree.tag_configure("medium", foreground=COLOR_MEDIUM)

        # ── 7. Overall risk summary bar ────────────────────────────────
        risk_frame = tk.Frame(self, bg="#313244", pady=6)
        risk_frame.pack(fill=tk.X, padx=12, pady=(4, 10))

        tk.Label(
            risk_frame, text="Overall Risk:",
            bg="#313244", fg=COLOR_FG,
            font=("Helvetica", 11, "bold"),
        ).pack(side=tk.LEFT, padx=12)

        self.risk_label = tk.Label(
            risk_frame, text="—",
            bg="#313244", fg=COLOR_FG,
            font=("Helvetica", 14, "bold"),
        )
        self.risk_label.pack(side=tk.LEFT, padx=6)

        self.score_label = tk.Label(
            risk_frame, text="",
            bg="#313244", fg="#6c7086",
            font=("Helvetica", 10),
        )
        self.score_label.pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Scan Control
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        """Validate inputs, run reachability check, then start the scan."""
        ip        = self.ip_var.get().strip()
        start_str = self.start_var.get().strip()
        end_str   = self.end_var.get().strip()

        # ── Input validation ───────────────────────────────────────────
        if not validate_ipv4(ip):
            messagebox.showerror("Invalid Input",
                                 f"'{ip}' is not a valid IPv4 address.")
            return

        try:
            start_port = int(start_str)
            end_port   = int(end_str)
        except ValueError:
            messagebox.showerror("Invalid Input", "Port values must be integers.")
            return

        if not (0 < start_port <= 65535 and 0 < end_port <= 65535):
            messagebox.showerror("Invalid Input",
                                 "Ports must be between 1 and 65535.")
            return

        if start_port > end_port:
            messagebox.showerror("Invalid Input",
                                 "Start port must be ≤ end port.")
            return

        # ── Pre-scan reachability check ────────────────────────────────
        # Runs on the main thread before launching the engine.
        # Warns the user if the host looks unreachable, but lets them
        # proceed anyway — the host may simply have common ports closed.
        self.progress_label.config(text=f"Checking if {ip} is reachable…")
        self.update_idletasks()   # force the label to repaint immediately

        if not is_host_reachable(ip):
            proceed = messagebox.askyesno(
                "Host May Be Unreachable",
                f"{ip} did not respond on any common probe ports "
                f"(80, 443, 22, 445, 8080).\n\n"
                f"The host may be offline, behind a firewall, or simply "
                f"have none of those ports open.\n\n"
                f"Proceed with the full scan anyway?",
            )
            if not proceed:
                self.progress_label.config(text="Scan cancelled.")
                return

        # ── Reset UI ───────────────────────────────────────────────────
        self.tree.delete(*self.tree.get_children())
        self._results.clear()
        self.progress_bar["value"]   = 0
        self.progress_bar["maximum"] = end_port - start_port + 1
        self.risk_label.config(text="Scanning…", fg=COLOR_FG)
        self.score_label.config(text="")
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_export.config(state=tk.DISABLED)
        self.btn_sort_status.config(state=tk.DISABLED)
        self.btn_sort_risk.config(state=tk.DISABLED)

        # Record start time for elapsed counter and export
        self._scan_start_time = time.time()
        self._update_timer()   # kick off the live MM:SS counter

        self.progress_label.config(
            text=f"Scanning {ip}  ports {start_port}–{end_port}  00:00 elapsed"
        )

        # ── Launch engine ──────────────────────────────────────────────
        self._engine = PortScannerEngine(
            host        = ip,
            start_port  = start_port,
            end_port    = end_port,
            on_result   = self._thread_on_result,
            on_progress = self._thread_on_progress,
            on_complete = self._thread_on_complete,
        )
        self._scan_thread = threading.Thread(
            target=self._engine.run, daemon=True
        )
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        """Signal the engine to stop."""
        if self._engine:
            self._engine.stop()
        self.progress_label.config(text="Scan stopped by user.")
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_start.config(state=tk.NORMAL)

    # ------------------------------------------------------------------
    # Elapsed Timer
    # ------------------------------------------------------------------

    def _update_timer(self) -> None:
        # Only keep ticking while a scan is active
        if self.btn_stop["state"] == tk.NORMAL:
            elapsed     = int(time.time() - self._scan_start_time)
            mins, secs  = divmod(elapsed, 60)
            ip          = self.ip_var.get().strip()
            try:
                s = int(self.start_var.get())
                e = int(self.end_var.get())
                port_range = f"ports {s}–{e}"
            except ValueError:
                port_range = ""
            self.progress_label.config(
                text=f"Scanning {ip}  {port_range}  "
                     f"{mins:02d}:{secs:02d} elapsed"
            )
            self.after(1000, self._update_timer)

    # ------------------------------------------------------------------
    # Thread → GUI callbacks (append only — never touch widgets)
    # ------------------------------------------------------------------

    def _thread_on_result(self, port: int, is_open: bool,
                          service: str, banner: str) -> None:
        with self._lock:
            self._pending_updates.append(("result", port, is_open, service, banner))

    def _thread_on_progress(self, current: int, total: int) -> None:
        with self._lock:
            self._pending_updates.append(("progress", current, total))

    def _thread_on_complete(self) -> None:
        with self._lock:
            self._pending_updates.append(("complete",))

    # ------------------------------------------------------------------
    # Polling loop — apply queued updates on the main thread
    # ------------------------------------------------------------------

    def _poll_updates(self) -> None:
        """Drain pending updates every 50 ms. Never blocks."""
        with self._lock:
            updates = list(self._pending_updates)
            self._pending_updates.clear()

        for update in updates:
            kind = update[0]
            if kind == "result":
                _, port, is_open, service, banner = update
                self._apply_result(port, is_open, service, banner)
            elif kind == "progress":
                _, current, total = update
                self._apply_progress(current, total)
            elif kind == "complete":
                self._apply_complete()

        self.after(50, self._poll_updates)

    def _apply_result(self, port: int, is_open: bool,
                      service: str, banner: str) -> None:
        """Insert one port result into the Treeview and _results list."""
        status = "Open" if is_open else "Closed"

        if is_open:
            weight = get_risk_weight(service)
            if weight >= 4:
                risk_str = f"🔴 High ({weight})"
                tag = ("open", "high")
            elif weight >= 2:
                risk_str = f"🟡 Medium ({weight})"
                tag = ("open", "medium")
            else:
                risk_str = f"🟢 Low ({weight})"
                tag = ("open",)
        else:
            risk_str = "—"
            banner   = ""
            tag      = ("closed",)

        self.tree.insert(
            "", tk.END,
            values=(port, status, service, banner, risk_str),
            tags=tag,
        )

        self._results.append({
            "port":    port,
            "status":  status,
            "service": service if is_open else "-",
            "banner":  banner,
        })

    def _apply_progress(self, current: int, total: int) -> None:
        """Update the progress bar value."""
        self.progress_bar["value"] = current

    def _apply_complete(self) -> None:
        """Called when the engine has finished scanning all ports."""
        elapsed     = time.time() - self._scan_start_time
        mins, secs  = divmod(int(elapsed), 60)

        self.progress_label.config(
            text=f"Scan complete ✓  —  {mins:02d}:{secs:02d}"
        )
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.NORMAL)
        self.btn_sort_status.config(state=tk.NORMAL)
        self.btn_sort_risk.config(state=tk.NORMAL)
        self._update_risk_summary()
        # Show the scan summary popup
        self._show_scan_summary(elapsed)

    def _update_risk_summary(self) -> None:
        """Recalculate total risk score and update the summary bar."""
        open_results = [r for r in self._results if r["status"] == "Open"]
        total_score  = sum(get_risk_weight(r["service"]) for r in open_results)
        label, emoji = calculate_risk_level(total_score)

        color = {"Low": COLOR_LOW, "Medium": COLOR_MEDIUM, "High": COLOR_HIGH}[label]
        self.risk_label.config(text=f"{emoji}  {label}", fg=color)
        self.score_label.config(
            text=f"  (score: {total_score}  |  {len(open_results)} open port(s))"
        )

    # ------------------------------------------------------------------
    # Risk Info Dialog
    # ------------------------------------------------------------------

    def _show_risk_info(self) -> None:
        win = tk.Toplevel(self)
        win.title("Risk Rating Guide")
        win.configure(bg=COLOR_BG)
        win.resizable(False, False)
        win.grab_set()   # modal — focus stays here until closed

        # ── Header ────────────────────────────────────────────────────
        tk.Label(
            win, text="Risk Rating Guide",
            font=("Helvetica", 14, "bold"),
            bg=COLOR_BG, fg=COLOR_ACCENT,
        ).pack(padx=20, pady=(16, 4))

        tk.Label(
            win,
            text="Weights are based on real CVE severity scores and exploitation history.",
            font=("Helvetica", 9), bg=COLOR_BG, fg="#6c7086",
        ).pack(padx=20, pady=(0, 12))

        # ── Per-service table ──────────────────────────────────────────
        table_frame = tk.Frame(win, bg=COLOR_BG)
        table_frame.pack(padx=20, pady=4, fill=tk.X)

        headers = ("Weight", "Level", "Services", "Reason")
        col_widths = (6, 10, 28, 48)

        rows = [
            ("5", "🔴 Critical", "Telnet",
             "Plaintext credentials — zero encryption"),
            ("4", "🔴 High",
             "RDP, SMB, MySQL, MSSQL,\nOracle, PostgreSQL,\nRedis, MongoDB, VNC",
             "Wormable RCEs (BlueKeep, EternalBlue)\nor unauthenticated DB exposure"),
            ("3", "🟠 Med-High",
             "FTP, TFTP, SNMP,\nNetBIOS",
             "Plaintext auth or\nno authentication"),
            ("2", "🟡 Medium",
             "SSH, SMTP, POP3, IMAP,\nLDAP, RPC",
             "Encrypted but invites\nbrute-force attacks"),
            ("1", "🟢 Low",
             "HTTP, HTTPS, DNS,\nNTP, DHCP",
             "Expected public services —\nrisk is in the application"),
        ]

        # Header row
        for col, (h, w) in enumerate(zip(headers, col_widths)):
            tk.Label(
                table_frame, text=h,
                font=("Helvetica", 9, "bold"),
                bg="#313244", fg=COLOR_ACCENT,
                width=w, anchor=tk.W, padx=6, pady=3,
                relief=tk.FLAT,
            ).grid(row=0, column=col, padx=1, pady=1, sticky=tk.W)

        # Data rows
        row_bg = [COLOR_ROW_B, "#252535"]
        for r_idx, (weight, level, services, reason) in enumerate(rows, start=1):
            bg = row_bg[r_idx % 2]
            for col, (text, w) in enumerate(
                zip((weight, level, services, reason), col_widths)
            ):
                tk.Label(
                    table_frame, text=text,
                    font=("Helvetica", 9),
                    bg=bg, fg=COLOR_FG,
                    width=w, anchor=tk.W, padx=6, pady=4,
                    justify=tk.LEFT,
                ).grid(row=r_idx, column=col, padx=1, pady=1, sticky=tk.W)

        # ── Overall score thresholds ───────────────────────────────────
        sep = tk.Frame(win, bg="#313244", height=1)
        sep.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(
            win, text="Overall Scan Score Thresholds",
            font=("Helvetica", 11, "bold"),
            bg=COLOR_BG, fg=COLOR_FG,
        ).pack(padx=20, anchor=tk.W)

        threshold_frame = tk.Frame(win, bg=COLOR_BG)
        threshold_frame.pack(padx=20, pady=6, fill=tk.X)

        thresholds = [
            ("🟢 Low",    "Total score  0 – 5",   COLOR_LOW),
            ("🟡 Medium", "Total score  6 – 12",  COLOR_MEDIUM),
            ("🔴 High",   "Total score  13+",      COLOR_HIGH),
        ]
        for label_text, range_text, color in thresholds:
            row = tk.Frame(threshold_frame, bg=COLOR_BG)
            row.pack(anchor=tk.W, pady=2)
            tk.Label(row, text=label_text,
                     font=("Helvetica", 10, "bold"),
                     bg=COLOR_BG, fg=color, width=12,
                     anchor=tk.W).pack(side=tk.LEFT)
            tk.Label(row, text=range_text,
                     font=("Helvetica", 10),
                     bg=COLOR_BG, fg=COLOR_FG).pack(side=tk.LEFT, padx=8)

        # ── CVE references ─────────────────────────────────────────────
        sep2 = tk.Frame(win, bg="#313244", height=1)
        sep2.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(
            win, text="Key CVE References",
            font=("Helvetica", 11, "bold"),
            bg=COLOR_BG, fg=COLOR_FG,
        ).pack(padx=20, anchor=tk.W)

        cves = [
            "CVE-2019-0708  BlueKeep   — RDP unauthenticated RCE        CVSS 9.8",
            "CVE-2017-0144  EternalBlue — SMB remote code execution      CVSS 8.1",
            "CVE-2022-0543  Redis RCE  — Lua sandbox escape              CVSS 10.0",
            "CVE-2019-15681 VNC        — memory disclosure / RCE         CVSS 9.8",
            "CVE-2017-6736  Cisco SNMP — unauthenticated RCE             CVSS 9.8",
        ]
        for cve in cves:
            tk.Label(
                win, text=f"  {cve}",
                font=("Courier", 9),
                bg=COLOR_BG, fg="#a6adc8",
                anchor=tk.W,
            ).pack(padx=20, anchor=tk.W)

        # ── Close button ───────────────────────────────────────────────
        tk.Button(
            win, text="Close",
            command=win.destroy,
            bg="#404040", fg="white",
            activebackground="#505050", activeforeground="white",
            font=("Helvetica", 10, "bold"),
            relief=tk.FLAT, padx=20, pady=6, cursor="hand2",
        ).pack(pady=(14, 18))

    # ------------------------------------------------------------------
    # Scan Summary Dialog
    # ------------------------------------------------------------------

    def _show_scan_summary(self, elapsed_seconds: float) -> None:
        open_results = [r for r in self._results if r["status"] == "Open"]
        total_score  = sum(get_risk_weight(r["service"]) for r in open_results)
        label, emoji = calculate_risk_level(total_score)

        highest = max(open_results,
                      key=lambda r: get_risk_weight(r["service"]),
                      default=None)
        highest_str = (
            f"{highest['service']} (port {highest['port']}, "
            f"weight {get_risk_weight(highest['service'])})"
            if highest else "None"
        )

        mins, secs = divmod(int(elapsed_seconds), 60)
        time_str   = f"{mins:02d}:{secs:02d}"

        risk_color = {
            "Low":    COLOR_LOW,
            "Medium": COLOR_MEDIUM,
            "High":   COLOR_HIGH,
        }[label]

        win = tk.Toplevel(self)
        win.title("Scan Summary")
        win.configure(bg=COLOR_BG)
        win.resizable(False, False)
        # Non-modal so user can see the table while reading the summary
        win.lift()
        win.focus_set()

        tk.Label(
            win, text="Scan Complete",
            font=("Helvetica", 14, "bold"),
            bg=COLOR_BG, fg=COLOR_ACCENT,
        ).pack(padx=24, pady=(16, 10))

        # Summary rows as a simple two-column grid
        summary_frame = tk.Frame(win, bg="#313244")
        summary_frame.pack(padx=24, pady=4, fill=tk.X)

        def summary_row(label_text, value_text, value_color=COLOR_FG, row=0):
            tk.Label(
                summary_frame, text=label_text,
                font=("Helvetica", 10), bg="#313244",
                fg="#6c7086", anchor=tk.W, width=20,
            ).grid(row=row, column=0, padx=(12, 4), pady=5, sticky=tk.W)
            tk.Label(
                summary_frame, text=value_text,
                font=("Helvetica", 10, "bold"),
                bg="#313244", fg=value_color, anchor=tk.W,
            ).grid(row=row, column=1, padx=(4, 12), pady=5, sticky=tk.W)

        try:
            sp = int(self.start_var.get())
            ep = int(self.end_var.get())
            port_range = f"{sp} – {ep}"
        except ValueError:
            port_range = "—"

        summary_row("Target",           self.ip_var.get().strip(),       row=0)
        summary_row("Port Range",        port_range,                      row=1)
        summary_row("Ports Scanned",     str(len(self._results)),         row=2)
        summary_row("Open Ports",        str(len(open_results)),          row=3)
        summary_row("Closed Ports",
                    str(len(self._results) - len(open_results)),          row=4)
        summary_row("Time Taken",        time_str,                        row=5)
        summary_row("Risk Score",        str(total_score),                row=6)
        summary_row("Overall Risk",
                    f"{emoji}  {label}",
                    value_color=risk_color,                               row=7)
        summary_row("Highest Risk",      highest_str,                     row=8)

        # Colour-coded risk banner at the bottom of the dialog
        banner = tk.Frame(win, bg=risk_color, pady=8)
        banner.pack(fill=tk.X, padx=24, pady=(10, 4))
        tk.Label(
            banner,
            text=f"{emoji}  Overall Risk: {label}  (score {total_score})",
            font=("Helvetica", 11, "bold"),
            bg=risk_color, fg="white",
        ).pack()

        tk.Button(
            win, text="OK  —  View Results",
            command=win.destroy,
            bg="#1e6fa5", fg="white",
            activebackground="#2a80b9", activeforeground="white",
            font=("Helvetica", 10, "bold"),
            relief=tk.FLAT, padx=20, pady=8, cursor="hand2",
        ).pack(pady=(8, 18))

    # ------------------------------------------------------------------
    # Sorting
    # ------------------------------------------------------------------

    def _redraw_table(self, sorted_results: list[dict]) -> None:
        """Clear the Treeview and re-insert rows in sorted order."""
        self.tree.delete(*self.tree.get_children())
        self._results = []
        for row in sorted_results:
            is_open = row["status"] == "Open"
            service = row["service"] if is_open else "-"
            banner  = row.get("banner", "") if is_open else ""
            self._apply_result(row["port"], is_open, service, banner)

    def _sort_by_status(self) -> None:
        """Sort Open ports first (or Closed first on toggle)."""
        if not self._results:
            return
        asc = self._sort_status_asc
        sorted_data = sorted(
            self._results,
            key=lambda r: (0 if r["status"] == "Open" else 1),
            reverse=not asc,
        )
        self._sort_status_asc = not asc
        self.btn_sort_status.config(
            text=f"{'↑' if asc else '↓'}  Sort by Status"
        )
        self._redraw_table(sorted_data)

    def _sort_by_risk(self) -> None:
        """Sort by risk weight; closed ports always go to the bottom."""
        if not self._results:
            return
        asc = self._sort_risk_asc

        def risk_key(r):
            if r["status"] != "Open":
                return 9999 if asc else -1
            return get_risk_weight(r["service"])

        sorted_data = sorted(self._results, key=risk_key, reverse=not asc)
        self._sort_risk_asc = not asc
        self.btn_sort_risk.config(
            text=f"{'↑' if asc else '↓'}  Sort by Risk"
        )
        self._redraw_table(sorted_data)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export(self) -> None:
        """Write scan results to a JSON file chosen by the user."""
        if not self._results:
            messagebox.showinfo("No Data", "No scan results to export.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export Scan Results",
            defaultextension=".json",
            filetypes=[("JSON file", "*.json")],
        )
        if not filepath:
            return

        elapsed = time.time() - self._scan_start_time if self._scan_start_time else 0.0

        data = build_export_data(
            target_ip  = self.ip_var.get().strip(),
            start_port = int(self.start_var.get()),
            end_port   = int(self.end_var.get()),
            results    = self._results,
            duration_s = elapsed,
        )

        try:
            export_json(data, filepath)
            messagebox.showinfo("Export Successful",
                                f"Results saved to:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()