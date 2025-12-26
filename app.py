import os
import uuid
import logging
import traceback
import csv
import sys
import subprocess
import json
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm


# ============================================================
# CONFIG FILE
# ============================================================
CONFIG_FILE = "config.json"

DEFAULT_SETTINGS = {
    # Keep these keys for compatibility (not shown in settings UI anymore)
    "student_name": "Your Name Here",
    "course_name": "Operating Systems",
    "university": "North South University",
    "project_title": "Smart Event Logger",

    # Security settings
    "pin_enabled": False,
    "pin_hash": "",  # stores SHA256 hash of PIN (not the PIN itself)
}


# ============================================================
# PATHS
# ============================================================
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")
RECOVERY_DIR = "recovery"
RECOVERY_FILE = os.path.join(RECOVERY_DIR, "recovery.tmp")
EXPORT_DIR = "exports"

AUTOSAVE_INTERVAL_MS = 10_000
ROTATE_LOG_SIZE_BYTES = 1_000_000
LIVE_REFRESH_INTERVAL_MS = 2_000


# ============================================================
# UTIL
# ============================================================
def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(RECOVERY_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)


def load_settings():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = DEFAULT_SETTINGS.copy()
        merged.update(data)
        for k in DEFAULT_SETTINGS:
            if k not in merged:
                merged[k] = DEFAULT_SETTINGS[k]
        return merged
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(settings: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def rotate_log_if_needed():
    if not os.path.exists(LOG_FILE):
        return
    if os.path.getsize(LOG_FILE) < ROTATE_LOG_SIZE_BYTES:
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = os.path.join(LOG_DIR, f"app_{stamp}.log")
    try:
        os.rename(LOG_FILE, archive_name)
    except Exception:
        pass


def setup_logger():
    ensure_dirs()
    rotate_log_if_needed()

    logger = logging.getLogger("SmartEventLogger")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


LOGGER = setup_logger()


def parse_log_line(line: str):
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 5:
        return None

    ts = parts[0]
    level = parts[1]
    session_part = parts[2]
    event_part = parts[3]
    msg_part = "|".join(parts[4:]).strip()

    session_id = session_part.replace("SESSION=", "").strip() if "SESSION=" in session_part else ""
    event_name = event_part.replace("EVENT=", "").strip() if "EVENT=" in event_part else ""

    return {
        "timestamp": ts,
        "level": level,
        "session": session_id,
        "event": event_name,
        "message": msg_part,
        "raw": line.rstrip("\n"),
    }


def read_all_logs():
    ensure_dirs()
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return [line.rstrip("\n") for line in f.readlines()]
    except Exception:
        return []


def open_folder(path: str):
    path = os.path.abspath(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore
        elif sys.platform.startswith("darwin"):
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
        return True
    except Exception:
        return False


# ============================================================
# APP
# ============================================================
class SmartEventLoggerApp:
    def __init__(self, root: tk.Tk):
        self.root = root

        self.settings = load_settings()
        self.root.title(self.settings.get("project_title", "Smart Event Logger"))
        self.root.geometry("1200x780")

        self.session_id = str(uuid.uuid4())[:8]
        self.current_file_path = None

        # Dashboard counters
        self.count_total = 0
        self.count_info = 0
        self.count_warn = 0
        self.count_error = 0
        self.event_counts = {}
        self.last_error_time = None

        # Logs cache
        self.all_log_lines = []
        self._live_refresh_job = None
        self._last_log_signature = None

        # Catch Tk callback exceptions
        self.root.report_callback_exception = self._tk_exception_handler

        # ✅ Hide app first (security feel)
        self.root.withdraw()

        # ✅ PIN auth BEFORE showing UI
        if not self._auth_gate_if_needed():
            self.root.destroy()
            return

        # Build UI after login success
        self._build_ui()
        self.root.deiconify()

        # Recovery check
        self._try_recover_on_startup()

        # Log app start
        self.log_event("APP_START", f"Application started. SESSION={self.session_id}")

        # Autosave recovery
        self._autosave_loop()

        # Initial refresh
        self.refresh_all()

        # Key bindings
        self.root.bind("<Control-s>", lambda e: self.save_file())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

        # Live refresh ON by default
        self.live_refresh_var.set(True)
        self._live_refresh_loop()

    # ============================================================
    # UI
    # ============================================================
    def _build_ui(self):
        top = tk.Frame(self.root)
        top.pack(padx=10, pady=8, fill="x")
        tk.Label(top, text=f"SESSION: {self.session_id}", font=("Segoe UI", 10, "bold")).pack(side="left")

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(padx=10, pady=(0, 8), fill="x")

        tk.Button(btn_frame, text="Open File", width=12, command=self.open_file).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Save File", width=12, command=self.save_file).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Trigger Error", width=12, command=self.trigger_error).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Clear Logs", width=12, command=self.clear_logs).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Refresh Views", width=12, command=self.refresh_all).pack(side="left", padx=4)

        tk.Button(btn_frame, text="Export CSV", width=12, command=self.export_csv).pack(side="left", padx=14)
        tk.Button(btn_frame, text="Export Logs PDF", width=14, command=self.export_pdf).pack(side="left", padx=4)

        tk.Button(btn_frame, text="Open Exports Folder", width=18, command=self.open_exports_folder).pack(side="left", padx=8)

        # ✅ Report Settings now only shows Security section
        tk.Button(btn_frame, text="Report Settings", width=14, command=self.open_report_settings).pack(side="left", padx=6)

        # ✅ Manual lock button
        tk.Button(btn_frame, text="Lock Now", width=12, command=self.lock_now).pack(side="left", padx=6)

        self.live_refresh_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            btn_frame,
            text="Live Refresh (2s)",
            variable=self.live_refresh_var,
            command=self.on_toggle_live_refresh
        ).pack(side="left", padx=6)

        main = tk.Frame(self.root)
        main.pack(padx=10, pady=0, fill="both", expand=True)

        left = tk.Frame(main)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right = tk.Frame(main, width=340)
        right.pack(side="right", fill="y")

        tk.Label(left, text="Editor (File I/O demo):", anchor="w").pack(fill="x")
        self.editor = scrolledtext.ScrolledText(left, wrap="word", height=12)
        self.editor.pack(fill="both", expand=True, pady=(0, 10))

        filter_box = tk.LabelFrame(left, text="Log Search & Filter (like Windows Event Viewer)")
        filter_box.pack(fill="x", pady=(0, 8))

        row1 = tk.Frame(filter_box)
        row1.pack(fill="x", padx=8, pady=6)

        tk.Label(row1, text="Keyword:").pack(side="left")
        self.search_var = tk.StringVar(value="")
        tk.Entry(row1, textvariable=self.search_var, width=24).pack(side="left", padx=6)

        tk.Label(row1, text="Level:").pack(side="left")
        self.level_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            row1,
            textvariable=self.level_var,
            values=["ALL", "INFO", "WARNING", "ERROR"],
            width=10,
            state="readonly"
        ).pack(side="left", padx=6)

        tk.Label(row1, text="Event:").pack(side="left")
        self.event_filter_var = tk.StringVar(value="ALL")
        self.event_combo = ttk.Combobox(row1, textvariable=self.event_filter_var, values=["ALL"], width=18, state="readonly")
        self.event_combo.pack(side="left", padx=6)

        row2 = tk.Frame(filter_box)
        row2.pack(fill="x", padx=8, pady=(0, 8))

        tk.Label(row2, text="Session:").pack(side="left")
        self.session_filter_var = tk.StringVar(value="ALL")
        self.session_combo = ttk.Combobox(row2, textvariable=self.session_filter_var, values=["ALL"], width=18, state="readonly")
        self.session_combo.pack(side="left", padx=6)

        tk.Button(row2, text="Apply Filter", command=self.apply_filter).pack(side="left", padx=8)
        tk.Button(row2, text="Reset Filter", command=self.reset_filter).pack(side="left", padx=4)

        tk.Label(left, text=f"Log Viewer ({LOG_FILE}):", anchor="w").pack(fill="x")
        self.log_viewer = scrolledtext.ScrolledText(left, wrap="none", height=12, state="disabled")
        self.log_viewer.pack(fill="both", expand=True)

        tk.Label(right, text="Smart Dashboard", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))

        self.health_var = tk.StringVar(value="Health: --")
        self.summary_var = tk.StringVar(value="Summary: --")
        self.top_actions_var = tk.StringVar(value="Top Actions: --")
        self.last_error_var = tk.StringVar(value="Last Error: --")

        tk.Label(right, textvariable=self.health_var, justify="left", anchor="w").pack(fill="x", pady=4)
        tk.Label(right, textvariable=self.summary_var, justify="left", anchor="w").pack(fill="x", pady=4)
        tk.Label(right, textvariable=self.top_actions_var, justify="left", anchor="w", wraplength=320).pack(fill="x", pady=4)
        tk.Label(right, textvariable=self.last_error_var, justify="left", anchor="w", wraplength=320).pack(fill="x", pady=4)

        tips = (
            "Tips:\n"
            "• Ctrl+O open file\n"
            "• Ctrl+S save file\n"
            "• Trigger Error logs traceback\n"
            "• Live refresh updates log view\n"
            "• Save clears editor automatically\n"
            "• PIN lock hides app until correct PIN\n"
            "• Lock Now locks the app anytime"
        )
        tk.Label(right, text=tips, justify="left", anchor="w").pack(fill="x", pady=(10, 0))

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(side="bottom", fill="x")

    def set_status(self, msg: str):
        if hasattr(self, "status_var"):
            self.status_var.set(msg)

    # ============================================================
    # LOCK NOW
    # ============================================================
    def lock_now(self):
        self.log_event("LOCK_NOW", "User locked the application manually.", "warning")
        self.set_status("Locked. Enter PIN to continue.")

        self.root.withdraw()

        if self._auth_gate_if_needed():
            self.root.deiconify()
            self.set_status("Unlocked successfully.")
            self.log_event("UNLOCK_SUCCESS", "User unlocked the application.")
        else:
            self.log_event("UNLOCK_FAILED", "Unlock failed or cancelled. Closing app.", "error")
            self.root.destroy()

    # ============================================================
    # PIN AUTH GATE
    # ============================================================
    def _auth_gate_if_needed(self) -> bool:
        enabled = bool(self.settings.get("pin_enabled", False))
        pin_hash = str(self.settings.get("pin_hash", "")).strip()

        if not enabled or not pin_hash:
            return True

        for attempt in range(1, 4):
            pin = self._pin_prompt(attempt)
            if pin is None:
                return False

            if sha256_text(pin) == pin_hash:
                self.log_event("AUTH_SUCCESS", f"PIN login success (attempt {attempt}).")
                return True
            else:
                self.log_event("AUTH_FAIL", f"PIN login failed (attempt {attempt}).", "warning")
                messagebox.showerror("Wrong PIN", f"Incorrect PIN. Attempts left: {3 - attempt}")

        messagebox.showerror("Access Denied", "Too many failed attempts. Closing application.")
        self.log_event("AUTH_LOCKOUT", "Too many failed PIN attempts.", "error")
        return False

    def _pin_prompt(self, attempt_no: int):
        win = tk.Toplevel(self.root)
        win.title("Security Check")
        win.geometry("360x180")
        win.resizable(False, False)
        win.grab_set()

        result = {"pin": None}

        tk.Label(win, text="Enter PIN to unlock", font=("Segoe UI", 10, "bold")).pack(pady=(14, 6))
        tk.Label(win, text=f"Attempt {attempt_no} of 3").pack(pady=(0, 10))

        pin_var = tk.StringVar(value="")
        entry = tk.Entry(win, textvariable=pin_var, show="*", width=20, justify="center")
        entry.pack()
        entry.focus_set()

        def ok():
            result["pin"] = pin_var.get()
            win.destroy()

        def cancel():
            result["pin"] = None
            win.destroy()

        btns = tk.Frame(win)
        btns.pack(pady=14)
        tk.Button(btns, text="Unlock", width=10, command=ok).pack(side="left", padx=6)
        tk.Button(btns, text="Cancel", width=10, command=cancel).pack(side="left", padx=6)

        win.bind("<Return>", lambda e: ok())
        win.bind("<Escape>", lambda e: cancel())

        self.root.wait_window(win)
        return result["pin"]

    # ============================================================
    # REPORT SETTINGS (ONLY SECURITY PART)
    # ============================================================
    def open_report_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Report Settings")
        win.geometry("520x330")
        win.resizable(False, False)

        frame = tk.Frame(win)
        frame.pack(padx=12, pady=12, fill="both", expand=True)

        v_pin_enabled = tk.BooleanVar(value=bool(self.settings.get("pin_enabled", False)))
        v_new_pin = tk.StringVar(value="")
        v_confirm_pin = tk.StringVar(value="")

        tk.Label(frame, text="Security (PIN Lock)", font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(4, 10)
        )

        tk.Checkbutton(frame, text="Enable PIN at startup", variable=v_pin_enabled).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=4
        )

        tk.Label(frame, text="New PIN (optional):", anchor="w").grid(row=2, column=0, sticky="w", pady=6)
        tk.Entry(frame, textvariable=v_new_pin, width=42, show="*").grid(row=2, column=1, sticky="w", pady=6)

        tk.Label(frame, text="Confirm PIN:", anchor="w").grid(row=3, column=0, sticky="w", pady=6)
        tk.Entry(frame, textvariable=v_confirm_pin, width=42, show="*").grid(row=3, column=1, sticky="w", pady=6)

        hint = tk.Label(
            frame,
            text="• Leave New PIN empty to keep current PIN.\n"
                 "• If PIN is enabled, you must set a PIN at least once.\n"
                 "• PIN is stored securely as a SHA256 hash in config.json.",
            justify="left"
        )
        hint.grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 4))

        def do_save():
            new_settings = self.settings.copy()
            new_settings["pin_enabled"] = bool(v_pin_enabled.get())
            new_settings["pin_hash"] = str(self.settings.get("pin_hash", "")).strip()

            new_pin = v_new_pin.get().strip()
            confirm = v_confirm_pin.get().strip()

            if new_pin or confirm:
                if new_pin != confirm:
                    messagebox.showerror("PIN Error", "New PIN and Confirm PIN do not match.")
                    return
                if len(new_pin) < 4:
                    messagebox.showerror("PIN Error", "PIN must be at least 4 characters.")
                    return
                new_settings["pin_hash"] = sha256_text(new_pin)

            if new_settings["pin_enabled"] and not new_settings["pin_hash"]:
                messagebox.showerror("PIN Required", "PIN is enabled but not set. Please enter a New PIN.")
                return

            if save_settings(new_settings):
                self.settings = new_settings
                self.log_event("SETTINGS_SAVED", "User updated security settings.")
                messagebox.showinfo("Saved", "Security settings saved!\n\nRestart the app to test startup PIN.")
                win.destroy()
            else:
                messagebox.showerror("Error", "Could not save settings. Check file permissions.")

        btns = tk.Frame(frame)
        btns.grid(row=5, column=0, columnspan=2, sticky="w", pady=12)

        tk.Button(btns, text="Save Settings", width=14, command=do_save).pack(side="left", padx=4)
        tk.Button(btns, text="Cancel", width=10, command=win.destroy).pack(side="left", padx=4)

    # ============================================================
    # LOGGING CORE
    # ============================================================
    def log_event(self, event_name: str, message: str, level: str = "info"):
        self.count_total += 1
        self.event_counts[event_name] = self.event_counts.get(event_name, 0) + 1
        payload = f"SESSION={self.session_id} | EVENT={event_name} | {message}"

        if level == "info":
            self.count_info += 1
            LOGGER.info(payload)
        elif level == "warning":
            self.count_warn += 1
            LOGGER.warning(payload)
        elif level == "error":
            self.count_error += 1
            self.last_error_time = datetime.now()
            LOGGER.error(payload)
        else:
            self.count_info += 1
            LOGGER.info(payload)

    def log_exception(self, event_name: str, exc: BaseException):
        trace = traceback.format_exc()
        self.last_error_time = datetime.now()
        self.count_error += 1
        self.count_total += 1
        self.event_counts[event_name] = self.event_counts.get(event_name, 0) + 1
        LOGGER.error(f"SESSION={self.session_id} | EVENT={event_name} | {str(exc)}\n{trace}")

    # ============================================================
    # FILE I/O (Save clears editor)
    # ============================================================
    def open_file(self):
        try:
            path = filedialog.askopenfilename(
                title="Open a file",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if not path:
                self.log_event("OPEN_CANCEL", "User cancelled open.", "warning")
                self.set_status("Open cancelled.")
                self.refresh_all()
                return

            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            self.editor.delete("1.0", "end")
            self.editor.insert("1.0", content)
            self.current_file_path = path

            self.log_event("FILE_OPEN", f"Opened file: {path}")
            self.set_status(f"Opened: {os.path.basename(path)}")
            self.refresh_all()
        except Exception as e:
            self._handle_error("FILE_OPEN_ERROR", e)

    def save_file(self):
        """
        After saving successfully -> clears editor automatically.
        """
        try:
            if self.current_file_path:
                path = self.current_file_path
            else:
                path = filedialog.asksaveasfilename(
                    title="Save file as",
                    defaultextension=".txt",
                    filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
                )
            if not path:
                self.log_event("SAVE_CANCEL", "User cancelled save.", "warning")
                self.set_status("Save cancelled.")
                self.refresh_all()
                return

            content = self.editor.get("1.0", "end-1c")

            if not content.strip():
                messagebox.showwarning("Empty Content", "Editor is empty. Write something before saving.")
                self.log_event("SAVE_EMPTY_BLOCKED", "Save blocked because editor was empty.", "warning")
                self.set_status("Save blocked (empty).")
                return

            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            self.current_file_path = path
            self.log_event("FILE_SAVE", f"Saved file: {path}")

            # ✅ Clear editor after save
            self.editor.delete("1.0", "end")
            self.log_event("EDITOR_CLEARED_AFTER_SAVE", "Editor cleared automatically after save.")

            # Clear recovery too
            self._clear_recovery_file()

            self.set_status(f"Saved & cleared editor: {os.path.basename(path)}")
            self.refresh_all()
        except Exception as e:
            self._handle_error("FILE_SAVE_ERROR", e)

    # ============================================================
    # CRASH RECOVERY
    # ============================================================
    def _autosave_loop(self):
        try:
            ensure_dirs()
            content = self.editor.get("1.0", "end-1c").strip()
            if content:
                with open(RECOVERY_FILE, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception:
            pass
        finally:
            self.root.after(AUTOSAVE_INTERVAL_MS, self._autosave_loop)

    def _try_recover_on_startup(self):
        try:
            if not os.path.exists(RECOVERY_FILE):
                return
            with open(RECOVERY_FILE, "r", encoding="utf-8") as f:
                data = f.read().strip()
            if not data:
                return

            ans = messagebox.askyesno("Recovery Found", "Unsaved work was found.\n\nRecover it now?")
            if ans:
                self.editor.delete("1.0", "end")
                self.editor.insert("1.0", data)
                self.log_event("RECOVERY_RESTORED", "Recovered unsaved work.", "warning")
                self.set_status("Recovered unsaved work.")
            else:
                self.log_event("RECOVERY_IGNORED", "User ignored recovery prompt.", "warning")
        except Exception as e:
            self._handle_error("RECOVERY_ERROR", e)

    def _clear_recovery_file(self):
        try:
            ensure_dirs()
            with open(RECOVERY_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass

    # ============================================================
    # ERROR TEST
    # ============================================================
    def trigger_error(self):
        try:
            self.log_event("ERROR_TEST", "Forcing division by zero.", "warning")
            _ = 10 / 0
        except Exception as e:
            self._handle_error("TRIGGERED_ERROR", e)

    def _tk_exception_handler(self, exc, val, tb):
        try:
            self.log_exception("TK_CALLBACK_EXCEPTION", val)
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{val}")
            self.set_status("Unexpected error occurred (logged).")
            self.refresh_all()
        except Exception:
            pass

    def _handle_error(self, event_name: str, exc: BaseException):
        try:
            ensure_dirs()
            content = self.editor.get("1.0", "end-1c").strip()
            if content:
                with open(RECOVERY_FILE, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception:
            pass

        self.log_exception(event_name, exc)
        messagebox.showerror(
            "Application Error",
            f"Reason: {exc}\n\nThe error was logged for debugging."
        )
        self.set_status(f"Error: {event_name} (logged).")
        self.refresh_all()

    # ============================================================
    # DASHBOARD
    # ============================================================
    def compute_health_score(self) -> int:
        score = 100
        score -= self.count_error * 7
        score -= self.count_warn * 3
        save_bonus = min(self.event_counts.get("FILE_SAVE", 0), 10)
        score += save_bonus
        return max(0, min(100, score))

    def _health_label(self, health: int) -> str:
        if health >= 90:
            return "Excellent"
        if health >= 75:
            return "Good"
        if health >= 55:
            return "Fair"
        return "Poor"

    def refresh_dashboard(self):
        top = sorted(self.event_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_text = ", ".join([f"{k}({v})" for k, v in top]) if top else "No actions yet."
        last_err = self.last_error_time.strftime("%Y-%m-%d %H:%M:%S") if self.last_error_time else "None"

        health = self.compute_health_score()
        label = self._health_label(health)

        self.health_var.set(f"Health: {health}/100 ({label})")
        self.summary_var.set(
            f"Summary:\n"
            f"• Total events: {self.count_total}\n"
            f"• Info: {self.count_info}\n"
            f"• Warnings: {self.count_warn}\n"
            f"• Errors: {self.count_error}"
        )
        self.top_actions_var.set(f"Top Actions:\n• {top_text}")
        self.last_error_var.set(f"Last Error:\n• {last_err}")

    # ============================================================
    # LOG VIEWER + FILTER
    # ============================================================
    def refresh_log_cache(self):
        self.all_log_lines = read_all_logs()

        events = set()
        sessions = set()
        for line in self.all_log_lines:
            parsed = parse_log_line(line)
            if parsed:
                if parsed["event"]:
                    events.add(parsed["event"])
                if parsed["session"]:
                    sessions.add(parsed["session"])

        event_values = ["ALL"] + sorted(events)
        session_values = ["ALL"] + sorted(sessions)

        self.event_combo["values"] = event_values
        self.session_combo["values"] = session_values

        if self.event_filter_var.get() not in event_values:
            self.event_filter_var.set("ALL")
        if self.session_filter_var.get() not in session_values:
            self.session_filter_var.set("ALL")

        self._last_log_signature = (len(self.all_log_lines), self.all_log_lines[-1] if self.all_log_lines else "")

    def show_logs(self, text: str):
        self.log_viewer.config(state="normal")
        self.log_viewer.delete("1.0", "end")
        self.log_viewer.insert("1.0", text)
        self.log_viewer.config(state="disabled")

    def refresh_log_viewer(self):
        self.refresh_log_cache()
        if not self.all_log_lines:
            self.show_logs("No logs yet.")
            return
        self.show_logs("\n".join(self.all_log_lines))

    def apply_filter(self):
        keyword = self.search_var.get().strip().lower()
        level = self.level_var.get().strip().upper()
        event_filter = self.event_filter_var.get().strip()
        session_filter = self.session_filter_var.get().strip()

        filtered = []
        for line in self.all_log_lines:
            parsed = parse_log_line(line)
            if not parsed:
                if not (keyword or level != "ALL" or event_filter != "ALL" or session_filter != "ALL"):
                    filtered.append(line)
                continue

            if level != "ALL" and parsed["level"].upper() != level:
                continue
            if event_filter != "ALL" and parsed["event"] != event_filter:
                continue
            if session_filter != "ALL" and parsed["session"] != session_filter:
                continue
            if keyword and keyword not in parsed["raw"].lower():
                continue

            filtered.append(parsed["raw"])

        self.show_logs("\n".join(filtered) if filtered else "No results match your filter.")
        self.set_status(f"Filter applied. Results: {len(filtered)} lines.")

    def reset_filter(self):
        self.search_var.set("")
        self.level_var.set("ALL")
        self.event_filter_var.set("ALL")
        self.session_filter_var.set("ALL")
        self.refresh_log_viewer()
        self.set_status("Filter reset.")

    # ============================================================
    # EXPORTS (Dashboard report removed)
    # ============================================================
    def export_csv(self):
        try:
            ensure_dirs()
            out_path = os.path.join(EXPORT_DIR, f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

            lines = self.log_viewer.get("1.0", "end-1c").splitlines()
            rows = []
            for line in lines:
                parsed = parse_log_line(line)
                if parsed:
                    rows.append(parsed)
                else:
                    rows.append({"timestamp": "", "level": "", "session": "", "event": "", "message": line, "raw": line})

            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "level", "session", "event", "message"])
                for r in rows:
                    w.writerow([r["timestamp"], r["level"], r["session"], r["event"], r["message"]])

            self.log_event("EXPORT_CSV", f"Exported CSV to: {out_path}")
            self.set_status("Exported CSV successfully.")
            messagebox.showinfo("Export CSV", f"CSV exported successfully:\n{out_path}")
            self.refresh_all()
        except Exception as e:
            self._handle_error("EXPORT_CSV_ERROR", e)

    def export_pdf(self):
        try:
            ensure_dirs()
            out_path = os.path.join(EXPORT_DIR, f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

            lines = self.log_viewer.get("1.0", "end-1c").splitlines()
            if not lines or (len(lines) == 1 and not lines[0].strip()):
                messagebox.showwarning("Export PDF", "No log content to export.")
                return

            c = canvas.Canvas(out_path, pagesize=A4)
            width, height = A4

            c.setFont("Helvetica-Bold", 14)
            c.drawString(2 * cm, height - 2 * cm, f"{self.settings.get('project_title', 'Smart Event Logger')} - Logs Export")

            c.setFont("Helvetica", 10)
            c.drawString(2 * cm, height - 2.7 * cm, f"Export time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(2 * cm, height - 3.2 * cm, f"Current session: {self.session_id}")

            y = height - 4 * cm
            c.setFont("Courier", 9)
            line_height = 0.45 * cm

            for line in lines:
                if y < 2 * cm:
                    c.showPage()
                    c.setFont("Courier", 9)
                    y = height - 2 * cm
                c.drawString(2 * cm, y, line[:140])
                y -= line_height

            c.save()

            self.log_event("EXPORT_PDF", f"Exported logs PDF to: {out_path}")
            self.set_status("Exported Logs PDF successfully.")
            messagebox.showinfo("Export PDF", f"PDF exported successfully:\n{out_path}")
            self.refresh_all()
        except Exception as e:
            self._handle_error("EXPORT_PDF_ERROR", e)

    def open_exports_folder(self):
        ensure_dirs()
        ok = open_folder(EXPORT_DIR)
        if ok:
            self.log_event("OPEN_EXPORTS_FOLDER", f"Opened exports folder: {os.path.abspath(EXPORT_DIR)}")
            self.set_status("Opened exports folder.")
        else:
            messagebox.showerror("Open Folder", "Could not open exports folder.")
            self.set_status("Failed to open exports folder.")

    # ============================================================
    # LIVE REFRESH
    # ============================================================
    def on_toggle_live_refresh(self):
        if self.live_refresh_var.get():
            self.set_status("Live refresh ON.")
            self._live_refresh_loop()
        else:
            self.set_status("Live refresh OFF.")
            if self._live_refresh_job is not None:
                try:
                    self.root.after_cancel(self._live_refresh_job)
                except Exception:
                    pass
                self._live_refresh_job = None

    def _live_refresh_loop(self):
        if not self.live_refresh_var.get():
            self._live_refresh_job = None
            return

        try:
            current_lines = read_all_logs()
            sig = (len(current_lines), current_lines[-1] if current_lines else "")
            if sig != self._last_log_signature:
                self.refresh_all()
                self.set_status("Live refresh: logs updated.")
        except Exception:
            pass

        self._live_refresh_job = self.root.after(LIVE_REFRESH_INTERVAL_MS, self._live_refresh_loop)

    # ============================================================
    # OTHER
    # ============================================================
    def clear_logs(self):
        try:
            ensure_dirs()
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
            self.log_event("LOG_CLEAR", "User cleared the log file.", "warning")
            self.set_status("Logs cleared.")
            self.refresh_all()
        except Exception as e:
            self._handle_error("LOG_CLEAR_ERROR", e)

    def refresh_all(self):
        self.refresh_log_viewer()
        self.refresh_dashboard()

    def on_exit(self):
        self.log_event("APP_EXIT", "Application closed by user.")
        self._clear_recovery_file()
        self.root.destroy()


# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    ensure_dirs()
    root = tk.Tk()
    app = SmartEventLoggerApp(root)
    root.mainloop()
