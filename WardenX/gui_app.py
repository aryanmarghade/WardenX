import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import customtkinter as ctk

import config
import scanner
import database

# Appearance Settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class WardenXApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("WardenX Security Center")
        self.geometry("820x680")
        self.minsize(740, 600)

        # Scanning State
        self.is_scanning = False

        self._build_ui()
        self._load_module_states()
        self._refresh_stats()

    def _build_ui(self):
        # Configure main grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # --- Header Section ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1c23")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="🛡️ WardenX Security Center",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#38bdf8"
        )
        self.title_label.pack(side="left", padx=20, pady=15)

        self.status_badge = ctk.CTkLabel(
            self.header_frame,
            text="SYSTEM ACTIVE",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#166534",
            text_color="#86efac",
            corner_radius=6,
            padx=12,
            pady=4
        )
        self.status_badge.pack(side="right", padx=20, pady=15)

        # --- Protection Modules Section ---
        self.modules_frame = ctk.CTkFrame(self, corner_radius=10)
        self.modules_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.modules_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.modules_title = ctk.CTkLabel(
            self.modules_frame,
            text="Real-Time Protection & Enforcement Layers",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.modules_title.grid(row=0, column=0, columnspan=3, padx=15, pady=(12, 8), sticky="w")

        # Row 1 Switches
        # 1. File System Protection Switch
        self.switch_file_watcher = ctk.CTkSwitch(
            self.modules_frame,
            text="File System Protection",
            font=ctk.CTkFont(size=13),
            command=self._on_toggle_file_watcher
        )
        self.switch_file_watcher.grid(row=1, column=0, padx=15, pady=6, sticky="w")

        # 2. Network Shield Switch
        self.switch_network = ctk.CTkSwitch(
            self.modules_frame,
            text="Network Shield",
            font=ctk.CTkFont(size=13),
            command=self._on_toggle_network_shield
        )
        self.switch_network.grid(row=1, column=1, padx=15, pady=6, sticky="w")

        # 3. Canary Honeypots Switch
        self.switch_canary = ctk.CTkSwitch(
            self.modules_frame,
            text="Canary Honeypots",
            font=ctk.CTkFont(size=13),
            command=self._on_toggle_canary
        )
        self.switch_canary.grid(row=1, column=2, padx=15, pady=6, sticky="w")

        # Row 2 Switches
        # 4. Browser Download Protection Switch (.crdownload / .part interception)
        self.switch_browser = ctk.CTkSwitch(
            self.modules_frame,
            text="Browser Download Protection",
            font=ctk.CTkFont(size=13),
            command=self._on_toggle_browser
        )
        self.switch_browser.grid(row=2, column=0, padx=15, pady=(6, 14), sticky="w")

        # 5. Strict HTTPS Enforcement Switch (Port 80 blocking)
        self.switch_https = ctk.CTkSwitch(
            self.modules_frame,
            text="Enforce Strict HTTPS",
            font=ctk.CTkFont(size=13),
            command=self._on_toggle_https
        )
        self.switch_https.grid(row=2, column=1, padx=15, pady=(6, 14), sticky="w")

        # --- Scanner Controls Section ---
        self.scan_frame = ctk.CTkFrame(self, corner_radius=10)
        self.scan_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        self.scan_frame.grid_columnconfigure(0, weight=1)

        self.scan_top_frame = ctk.CTkFrame(self.scan_frame, fg_color="transparent")
        self.scan_top_frame.pack(fill="x", padx=15, pady=(12, 8))

        self.scan_header_label = ctk.CTkLabel(
            self.scan_top_frame,
            text="On-Demand Threat Scanner",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.scan_header_label.pack(side="left")

        self.btn_scan = ctk.CTkButton(
            self.scan_top_frame,
            text="📁 Scan System/Directory",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self._start_scan_dialog
        )
        self.btn_scan.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(self.scan_frame)
        self.progress_bar.pack(fill="x", padx=15, pady=(8, 4))
        self.progress_bar.set(0)

        self.scan_status_label = ctk.CTkLabel(
            self.scan_frame,
            text="Ready to scan. Select a folder to begin threat analysis.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        self.scan_status_label.pack(fill="x", padx=15, pady=(0, 12))

        # --- Activity & Log Console Section ---
        self.log_frame = ctk.CTkFrame(self, corner_radius=10)
        self.log_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="nsew")
        self.log_frame.grid_columnconfigure(0, weight=1)
        self.log_frame.grid_rowconfigure(1, weight=1)

        self.stats_bar = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        self.stats_bar.grid(row=0, column=0, padx=15, pady=(10, 5), sticky="ew")

        self.lbl_stats = ctk.CTkLabel(
            self.stats_bar,
            text="Total Scans: 0 | Threats Neutralized: 0",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1"
        )
        self.lbl_stats.pack(side="left")

        self.btn_refresh = ctk.CTkButton(
            self.stats_bar,
            text="Refresh Stats",
            width=90,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            command=self._refresh_stats
        )
        self.btn_refresh.pack(side="right")

        self.log_textbox = ctk.CTkTextbox(
            self.log_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            activate_scrollbars=True
        )
        self.log_textbox.grid(row=1, column=0, padx=15, pady=(5, 15), sticky="nsew")
        self._append_log("WardenX GUI initialized. Ready.\n")

    def _load_module_states(self):
        fw_state = config.get_state("FILE_WATCHER_ACTIVE")
        ns_state = config.get_state("NETWORK_SHIELD_ACTIVE")
        canary_state = config.get_state("CANARY_ACTIVE")
        browser_state = config.get_state("BROWSER_PROTECTION_ACTIVE")
        https_state = config.get_state("FORCE_HTTPS_ACTIVE")

        if fw_state:
            self.switch_file_watcher.select()
        else:
            self.switch_file_watcher.deselect()

        if ns_state:
            self.switch_network.select()
        else:
            self.switch_network.deselect()

        if canary_state:
            self.switch_canary.select()
        else:
            self.switch_canary.deselect()

        if browser_state:
            self.switch_browser.select()
        else:
            self.switch_browser.deselect()

        if https_state:
            self.switch_https.select()
        else:
            self.switch_https.deselect()

    def _on_toggle_file_watcher(self):
        state = bool(self.switch_file_watcher.get())
        config.set_state("FILE_WATCHER_ACTIVE", state)
        self._append_log(f"[CONFIG] File System Protection -> {'ENABLED' if state else 'DISABLED'}")

    def _on_toggle_network_shield(self):
        state = bool(self.switch_network.get())
        config.set_state("NETWORK_SHIELD_ACTIVE", state)
        self._append_log(f"[CONFIG] Network Shield -> {'ENABLED' if state else 'DISABLED'}")

    def _on_toggle_canary(self):
        state = bool(self.switch_canary.get())
        config.set_state("CANARY_ACTIVE", state)
        self._append_log(f"[CONFIG] Canary Honeypots -> {'ENABLED' if state else 'DISABLED'}")

    def _on_toggle_browser(self):
        state = bool(self.switch_browser.get())
        config.set_state("BROWSER_PROTECTION_ACTIVE", state)
        self._append_log(f"[CONFIG] Browser Download Protection -> {'ENABLED' if state else 'DISABLED'}")

    def _on_toggle_https(self):
        state = bool(self.switch_https.get())
        config.set_state("FORCE_HTTPS_ACTIVE", state)
        self._append_log(f"[CONFIG] Enforce Strict HTTPS -> {'ENABLED' if state else 'DISABLED'}")

    def _start_scan_dialog(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return

        chosen_dir = filedialog.askdirectory(title="Select Directory to Scan with WardenX")
        if not chosen_dir:
            return

        self.is_scanning = True
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.progress_bar.set(0)
        self.scan_status_label.configure(text=f"Scanning target: {chosen_dir}...", text_color="#38bdf8")
        self._append_log(f"\n--- Starting Scan: {chosen_dir} ---")

        threading.Thread(target=self._run_scan_thread, args=(chosen_dir,), daemon=True).start()

    def _run_scan_thread(self, target_dir):
        def progress_update(current_file, current_idx, total, threats_found):
            fraction = current_idx / total if total > 0 else 0
            filename = os.path.basename(current_file)
            self.after(
                0,
                lambda: self._update_progress_ui(fraction, current_idx, total, filename, threats_found)
            )

        results = scanner.scan_directory(target_dir, progress_callback=progress_update)
        self.after(0, lambda: self._scan_completed(results, target_dir))

    def _update_progress_ui(self, fraction, current_idx, total, filename, threats_found):
        self.progress_bar.set(fraction)
        self.scan_status_label.configure(
            text=f"[{current_idx}/{total}] Scanning: {filename} (Threats: {threats_found})"
        )

    def _scan_completed(self, results, target_dir):
        self.is_scanning = False
        self.btn_scan.configure(state="normal", text="📁 Scan System/Directory")
        self.progress_bar.set(1.0)

        status_text = (
            f"Scan finished for {target_dir}. Scanned: {results['scanned']}, "
            f"Malicious: {results['malicious']}, Errors: {results['errors']}"
        )
        self.scan_status_label.configure(text=status_text, text_color="#4ade80" if results["malicious"] == 0 else "#f87171")
        self._append_log(f"[SCAN COMPLETE] {status_text}")

        if results["threats"]:
            self._append_log("--- Detected Threats ---")
            for t in results["threats"]:
                self._append_log(f"  ❌ {t['path']} -> Signature: {t['signature']}")

        self._refresh_stats()

        if results["malicious"] > 0:
            messagebox.showwarning(
                "Scan Completed - Threats Detected!",
                f"WardenX scanned {results['scanned']} file(s) in:\n{target_dir}\n\n"
                f"⚠️ Found {results['malicious']} potential threat(s)!\n"
                f"Review the activity log and quarantine records."
            )
        else:
            messagebox.showinfo(
                "Scan Completed - Clean",
                f"WardenX scanned {results['scanned']} file(s) in:\n{target_dir}\n\n"
                f"✅ No malicious files detected."
            )

    def _refresh_stats(self):
        try:
            total_scans, total_blocks = database.get_stats()
            self.lbl_stats.configure(
                text=f"Total Scans Logged: {total_scans} | Threats/Blocks: {total_blocks}"
            )
        except Exception:
            self.lbl_stats.configure(text="Stats: Database Unavailable")

    def _append_log(self, message):
        self.log_textbox.insert("end", message + "\n")
        self.log_textbox.see("end")


if __name__ == "__main__":
    app = WardenXApp()
    app.mainloop()
