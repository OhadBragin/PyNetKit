import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import threading
from scapy.all import conf, get_if_list
import scanner
import attacks
from utils import is_valid_ip, is_valid_port
import models
import ipaddress


class HostDetailWindow(tk.Toplevel):
    """
    A Toplevel window that displays detailed information about a Host,
    allows port scanning, and allows initiating attacks like ARP spoofing.
    """

    def __init__(self, master, host, scanner_obj, iface):
        """
        Initializes the detail window for a specific host.
        :param master: The parent window.
        :param host: The Host object to display.
        :param scanner_obj: The NetworkScanner instance to use for scanning.
        :param iface: The network interface to use.
        """
        super().__init__(master)
        self.title(f"Host Details: {host.ip_address}")
        self.geometry("450x650")
        self.host = host
        self.scanner = scanner_obj
        self.iface = iface
        self.arp_poisoner = None
        self._create_widgets()

    def _create_widgets(self):
        """
        Creates and arranges the widgets in the detail window.
        :return: None
        """
        # Host Information Section
        info_frame = tk.LabelFrame(self, text="Host Information", padx=10, pady=10)
        info_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(info_frame, text=f"IP Address: {self.host.ip_address}", font=("Arial", 10, "bold")).pack(anchor="w")
        tk.Label(info_frame, text=f"MAC Address: {self.host.mac_address}").pack(anchor="w")
        self.os_label = tk.Label(info_frame, text=f"Operating System: {self.host.os or 'Unknown'}")
        self.os_label.pack(anchor="w")

        # Port Scan Section
        port_scan_frame = tk.LabelFrame(self, text="Port Scan Configuration", padx=10, pady=10)
        port_scan_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(port_scan_frame, text="Port Range (e.g. 1-1024):").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(port_scan_frame, width=15)
        self.port_entry.insert(0, "1-1024")
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.scan_ports_btn = tk.Button(port_scan_frame, text="Scan Ports", command=self._start_port_scan)
        self.scan_ports_btn.pack(side=tk.RIGHT)

        # Open Ports Section
        ports_frame = tk.LabelFrame(self, text="Scan Results", padx=10, pady=10)
        ports_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.ports_list = scrolledtext.ScrolledText(ports_frame, height=10)
        self.ports_list.pack(fill="both", expand=True)
        self._refresh_ports_display()

        # Attacks Section
        attacks_frame = tk.LabelFrame(self, text="Initiate Attacks", padx=10, pady=10)
        attacks_frame.pack(fill="x", padx=10, pady=10)

        # Gateway Selection for ARP Spoof
        tk.Label(attacks_frame, text="Gateway IP:").pack(side=tk.LEFT)
        self.gateway_entry = tk.Entry(attacks_frame)
        # Suggest the first host as gateway by default
        if self.master.hosts:
             self.gateway_entry.insert(0, self.master.hosts[0].ip_address)
        self.gateway_entry.pack(side=tk.LEFT, padx=5)

        self.arp_btn = tk.Button(attacks_frame, text="Start ARP Spoof", command=self._toggle_arp_spoof)
        self.arp_btn.pack(side=tk.RIGHT, padx=5)

    def _refresh_ports_display(self):
        """
        Updates the scrolled text widget with the host's current open ports.
        :return: None
        """
        self.ports_list.config(state=tk.NORMAL)
        self.ports_list.delete(1.0, tk.END)
        open_ports = [p for p in self.host.ports if p.status == "open"]
        if open_ports:
            for p in open_ports:
                self.ports_list.insert(tk.END, f"Port {p.port_number}: {p.status}\n")
        else:
            self.ports_list.insert(tk.END, "No open ports found or scan not performed.\n")
        self.ports_list.config(state=tk.DISABLED)
        self.os_label.config(text=f"Operating System: {self.host.os or 'Unknown'}")

    def _start_port_scan(self):
        """
        Initiates a port scan in a background thread.
        :return: None
        """
        port_input = self.port_entry.get().strip()
        if not is_valid_port(port_input):
            messagebox.showerror("Error", "Invalid Port range format. Please read help(-h)")
            return

        port_str = port_input.split('-')
        if len(port_str) == 2:
            port_range = (int(port_str[0]), int(port_str[1]))
        else:
            port_range = (int(port_str[0]), int(port_str[0]))

        self.scan_ports_btn.config(state=tk.DISABLED, text="Scanning...")
        self.scanner.port_range = port_range
        
        thread = threading.Thread(target=self._run_port_scan)
        thread.daemon = True
        thread.start()

    def _run_port_scan(self):
        """
        Runs the port scan logic and updates the UI.
        :return: None
        """
        try:
            # Clear old ports
            self.host.ports = []
            self.scanner.scan_ports(self.host, self.iface)
            self.after(0, self._on_port_scan_complete)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Port Scan Error", str(e)))
            self.after(0, self._on_port_scan_complete)

    def _on_port_scan_complete(self):
        """
        Callback when port scan finishes.
        :return: None
        """
        self.scan_ports_btn.config(state=tk.NORMAL, text="Scan Ports")
        self._refresh_ports_display()

    def _toggle_arp_spoof(self):
        """
        Starts or stops the ARP spoofing attack.
        :return: None
        """
        if self.arp_poisoner and self.arp_poisoner.is_running:
            self._stop_arp_spoof()
        else:
            self._start_arp_spoof()

    def _start_arp_spoof(self):
        """
        Configures and starts the ArpPoisoning attack.
        :return: None
        """
        gateway_ip = self.gateway_entry.get().strip()
        if not gateway_ip:
            messagebox.showerror("Error", "Please specify a gateway IP.")
            return

        found_gw = next((h for h in self.master.hosts if h.ip_address == gateway_ip), None)
        if not found_gw:
            messagebox.showerror("Error", "Gateway MAC address not known. Ensure the gateway was in the scan range.")
            return

        self.arp_poisoner = attacks.ArpPoisoning(self.host, found_gw, self.iface)
        try:
            self.arp_poisoner.start()
            self.arp_btn.config(text="Stop ARP Spoof", fg="red")
            messagebox.showinfo("Success", f"Started ARP poisoning.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {str(e)}")

    def _stop_arp_spoof(self):
        """
        Stops the attack and restores tables.
        :return: None
        """
        if self.arp_poisoner:
            self.arp_poisoner.stop()
            self.arp_btn.config(text="Start ARP Spoof", fg="black")
            messagebox.showinfo("Stopped", "ARP tables restored.")


class NetworkMapperGUI(tk.Tk):
    """
    Main GUI application class.
    """

    def __init__(self):
        """
        Initializes the application window.
        """
        super().__init__()
        self.title("Network Mapper v1.1")
        self.geometry("800x600")
        self.hosts = []
        self.scanner = None
        self._create_widgets()

    def _create_widgets(self):
        """
        Creates the main window layout.
        :return: None
        """
        tk.Label(self, text="Network Mapper - Host Discovery", font=("Arial", 16, "bold"), pady=10).pack()

        input_frame = tk.LabelFrame(self, text="Scan Configuration", padx=10, pady=10)
        input_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(input_frame, text="IP Range:").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(input_frame, width=30)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(input_frame, text="Interface:").grid(row=1, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(input_frame, values=get_if_list(), width=27)
        try:
            self.iface_combo.set(conf.iface.name if hasattr(conf.iface, 'name') else conf.iface)
        except:
            if self.iface_combo['values']:
                self.iface_combo.current(0)
        self.iface_combo.grid(row=1, column=1, padx=5, pady=5)

        self.scan_btn = tk.Button(input_frame, text="Discover Hosts", command=self._start_host_discovery,
                                  bg="#2ecc71", fg="white", font=("Arial", 10, "bold"), padx=15)
        self.scan_btn.grid(row=0, column=2, rowspan=2, padx=20)

        self.status_label = tk.Label(self, text="Enter range and click Discover", fg="gray")
        self.status_label.pack()

        list_frame = tk.LabelFrame(self, text="Discovered Hosts (Click for details/Port Scan)", padx=10, pady=10)
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.canvas = tk.Canvas(list_frame)
        self.scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

    def _start_host_discovery(self):
        """
        Validates input and starts host discovery in background.
        :return: None
        """
        ip_range = self.ip_entry.get().strip()
        if not is_valid_ip(ip_range):
            messagebox.showerror("Error", f"Invalid IP address or range: {ip_range}")
            return

        iface = self.iface_combo.get()
        self.scan_btn.config(state=tk.DISABLED, text="Searching...")
        self.status_label.config(text=f"Searching for hosts in {ip_range}...", fg="blue")

        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        thread = threading.Thread(target=self._run_discovery, args=(ip_range, iface))
        thread.daemon = True
        thread.start()

    def _run_discovery(self, ip_range, iface):
        """
        Performs host discovery in background thread.
        :return: None
        """
        try:
            self.scanner = scanner.NetworkScanner(ip_range, (1, 1024)) # Default port range
            self.hosts = self.scanner.run_scan(iface)
            self.after(0, self._display_hosts)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Discovery Error", str(e)))
            self.after(0, self._reset_btn)

    def _display_hosts(self):
        """
        Updates UI with list of discovered hosts.
        :return: None
        """
        if not self.hosts:
             tk.Label(self.scrollable_frame, text="No active hosts found.").pack(pady=10)
        else:
            for host in self.hosts:
                text = f"IP: {host.ip_address:<15} | MAC: {host.mac_address}"
                btn = tk.Button(self.scrollable_frame, text=text, font=("Courier", 10),
                                anchor="w", padx=10, pady=5, command=lambda h=host: self._open_details(h))
                btn.pack(fill="x", pady=2)
        
        self.status_label.config(text=f"Found {len(self.hosts)} hosts.", fg="green")
        self._reset_btn()

    def _reset_btn(self):
        """
        Resets discovery button state.
        :return: None
        """
        self.scan_btn.config(state=tk.NORMAL, text="Discover Hosts")

    def _open_details(self, host):
        """
        Opens HostDetailWindow for host.
        :return: None
        """
        HostDetailWindow(self, host, self.scanner, self.iface_combo.get())

if __name__ == "__main__":
    app = NetworkMapperGUI()
    app.mainloop()
