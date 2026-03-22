import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import AsyncSniffer, IP, TCP, get_if_list, conf
import threading
import time
from collections import defaultdict
from datetime import datetime
import os
import ctypes


class MiniIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini Intrusion Detection System")
        self.root.geometry("760x520")

        # State
        self.is_sniffing = False
        self.sniffer = None
        self.log_file = "ids_alerts.log"
        self.lock = threading.Lock()

        # Threat detection thresholds
        self.TIME_WINDOW = 5
        self.SYN_THRESHOLD = 20
        self.PORT_THRESHOLD = 15
        self.CONN_THRESHOLD = 100

        # Tracking
        self.syn_counts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.conn_counts = defaultdict(int)
        self.alerted_syn = set()
        self.alerted_ports = set()
        self.alerted_conn = set()
        self.last_reset = time.time()

        # Interfaces
        self.interfaces = self.get_interfaces()

        self.setup_ui()
        self.log_message("System initialized. Awaiting start command...")

    def get_interfaces(self):
        try:
            ifaces = get_if_list()
            clean = []
            seen = set()
            for iface in ifaces:
                name = str(iface).strip()
                if name and name not in seen:
                    clean.append(name)
                    seen.add(name)
            return clean
        except Exception:
            return []

    def get_default_interface(self):
        preferred_keywords = [
            "Npcap Loopback Adapter",
            "Wi-Fi",
            "Wireless",
            "Ethernet",
        ]

        for keyword in preferred_keywords:
            for iface in self.interfaces:
                if keyword.lower() in iface.lower():
                    return iface

        try:
            return str(conf.iface)
        except Exception:
            return self.interfaces[0] if self.interfaces else ""

    def setup_ui(self):
        header_frame = tk.Frame(self.root)
        header_frame.pack(pady=10, fill=tk.X)

        self.status_label = tk.Label(
            header_frame,
            text="Status: Stopped",
            fg="red",
            font=("Arial", 12, "bold")
        )
        self.status_label.grid(row=0, column=0, padx=15, sticky="w")

        self.start_btn = tk.Button(
            header_frame,
            text="Start IDS",
            bg="green",
            fg="white",
            command=self.start_sniffing
        )
        self.start_btn.grid(row=0, column=1, padx=8)

        self.stop_btn = tk.Button(
            header_frame,
            text="Stop IDS",
            bg="red",
            fg="white",
            command=self.stop_sniffing,
            state=tk.DISABLED
        )
        self.stop_btn.grid(row=0, column=2, padx=8)

        iface_frame = tk.Frame(self.root)
        iface_frame.pack(padx=20, pady=5, fill=tk.X)

        tk.Label(iface_frame, text="Interface:").pack(side=tk.LEFT)

        self.iface_var = tk.StringVar(value=self.get_default_interface())
        self.iface_combo = ttk.Combobox(
            iface_frame,
            textvariable=self.iface_var,
            values=self.interfaces,
            state="readonly",
            width=55
        )
        self.iface_combo.pack(side=tk.LEFT, padx=10)

        refresh_btn = tk.Button(
            iface_frame,
            text="Refresh Interfaces",
            command=self.refresh_interfaces
        )
        refresh_btn.pack(side=tk.LEFT)

        info_label = tk.Label(
            self.root,
            text="Tip: Use 'Npcap Loopback Adapter' for localhost tests, or 'Wi-Fi' for LAN tests.",
            fg="gray"
        )
        info_label.pack(anchor="w", padx=20, pady=(0, 8))

        log_frame = tk.Frame(self.root)
        log_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(log_frame, text="Real-Time Security Alerts:").pack(anchor="w")
        self.log_area = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def refresh_interfaces(self):
        self.interfaces = self.get_interfaces()
        self.iface_combo["values"] = self.interfaces
        if self.interfaces and self.iface_var.get() not in self.interfaces:
            self.iface_var.set(self.get_default_interface())
        self.log_message("Interface list refreshed.")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception:
            pass

        self.root.after(0, self._update_gui_log, log_entry)

    def _update_gui_log(self, text):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, text)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def reset_trackers(self):
        with self.lock:
            self.syn_counts.clear()
            self.port_scans.clear()
            self.conn_counts.clear()
            self.alerted_syn.clear()
            self.alerted_ports.clear()
            self.alerted_conn.clear()
            self.last_reset = time.time()

    def start_sniffing(self):
        if self.is_sniffing:
            return

        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showerror("Interface Error", "Please select a network interface.")
            return

        self.reset_trackers()
        self.is_sniffing = True
        self.status_label.config(text="Status: Running", fg="green")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.iface_combo.config(state="disabled")

        self.log_message(f"Starting intrusion detection engine on interface: {iface}")

        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                prn=self.process_packet,
                store=False,
                filter="ip"
            )
            self.sniffer.start()
        except Exception as e:
            self.is_sniffing = False
            self.status_label.config(text="Status: Stopped", fg="red")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.iface_combo.config(state="readonly")
            messagebox.showerror("Sniffer Error", f"Failed to start packet capture:\n{e}")
            self.log_message(f"[ERROR] Failed to start sniffer: {e}")

    def stop_sniffing(self):
        if not self.is_sniffing:
            return

        self.is_sniffing = False

        try:
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
        except Exception as e:
            self.log_message(f"[ERROR] Failed to stop sniffer cleanly: {e}")

        self.status_label.config(text="Status: Stopped", fg="red")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_combo.config(state="readonly")
        self.log_message("Intrusion detection engine stopped.")

    def process_packet(self, packet):
        if not self.is_sniffing:
            return

        current_time = time.time()
        if current_time - self.last_reset > self.TIME_WINDOW:
            self.reset_trackers()

        if IP not in packet:
            return

        src_ip = packet[IP].src

        with self.lock:
            self.conn_counts[src_ip] += 1

            if (
                self.conn_counts[src_ip] >= self.CONN_THRESHOLD
                and src_ip not in self.alerted_conn
            ):
                self.alerted_conn.add(src_ip)
                self.log_message(f"[ALERT] High traffic volume detected from {src_ip}")

            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = int(packet[TCP].flags)

                # SYN only: SYN set, ACK not set
                is_syn_only = (flags & 0x02) and not (flags & 0x10)

                if is_syn_only:
                    self.syn_counts[src_ip] += 1

                    if (
                        self.syn_counts[src_ip] >= self.SYN_THRESHOLD
                        and src_ip not in self.alerted_syn
                    ):
                        self.alerted_syn.add(src_ip)
                        self.log_message(f"[ALERT] Potential SYN Flood detected from {src_ip}")

                    self.port_scans[src_ip].add(dst_port)

                    if (
                        len(self.port_scans[src_ip]) >= self.PORT_THRESHOLD
                        and src_ip not in self.alerted_ports
                    ):
                        self.alerted_ports.add(src_ip)
                        self.log_message(
                            f"[ALERT] Port Scan detected from {src_ip} targeting {len(self.port_scans[src_ip])} ports"
                        )


def is_admin():
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


if __name__ == "__main__":
    root = tk.Tk()
    app = MiniIDS(root)

    if not is_admin():
        messagebox.showwarning(
            "Permissions",
            "Warning: Admin/root privileges are recommended for packet capture.\n"
            "On Windows, run Python or your terminal as Administrator."
        )

    root.mainloop()