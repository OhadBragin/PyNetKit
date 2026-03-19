import threading
from typing import Optional, List, Any, Dict, Union, Tuple
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox
from scapy.interfaces import get_working_ifaces
from scapy.all import conf

from scanner import NetworkScanner, TraceScanner
from attacks import ArpPoisoning, DHCPStarvation, SingleTargetDos
from utils import get_gateway, get_mac_by_ip, is_valid_ip
import models


class NetworkMapperGUI(tb.Window):
    """
    Graphical User Interface for the Network Mapper Tool.
    """

    def __init__(self) -> None:
        """
        Initializes the GUI window and its components.
        :return: None
        """
        super().__init__(themename="darkly") # Clean, professional dark mode
        self.title("PyNetKit")
        self.geometry("1000x800") # More responsive default size
        
        self.interfaces: Dict[str, str] = {}
        self.populate_interfaces()
        
        self.active_host: Optional[models.Host] = None # Keep track of selected host
        self.ports_need_refresh: bool = False # Optimization for tab loading
        
        # Global attacks variables
        self.arp_attack: Optional[ArpPoisoning] = None
        self.st_dos_attack: Optional[SingleTargetDos] = None
        self.dhcp_attack: Optional[DHCPStarvation] = None
        
        self.setup_ui()
        self.select_default_interface()
        
        # Dynamically set the minimum size so buttons never get cut off
        self.update_idletasks()
        self.minsize(self.winfo_reqwidth(), self.winfo_reqheight())
        
    def populate_interfaces(self) -> None:
        """
        Populates the internal interface mapping by scanning available network interfaces.
        :return: None
        """
        for iface in get_working_ifaces():
            friendly_name = iface.description if iface.description else iface.name
            if friendly_name in self.interfaces:
                friendly_name = f"{friendly_name} ({iface.name})"
            self.interfaces[friendly_name] = iface.name
            
    def select_default_interface(self) -> None:
        """
        Selects Scapy's default interface in the interface selection dropdown.
        :return: None
        """
        default_iface_name = str(conf.iface)
        for friendly, real in self.interfaces.items():
            if real == default_iface_name:
                self.iface_combo.set(friendly)
                break
        else:
            if self.interfaces:
                self.iface_combo.current(0)
            
    def setup_ui(self) -> None:
        """
        Sets up the main UI layout using a PanedWindow.
        :return: None
        """
        # Create a PanedWindow to split top and bottom halves
        self.paned_window = tb.Panedwindow(self, orient=VERTICAL)
        self.paned_window.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # --- TOP HALF: Master View (Discovery & List) ---
        self.top_frame = tb.Frame(self.paned_window)
        self.paned_window.add(self.top_frame, weight=1) # Top gets 1 part height
        
        self.setup_master_view()
        
        # --- BOTTOM HALF: Detail View (Notebook for active host) ---
        self.bottom_frame = tb.Frame(self.paned_window)
        self.paned_window.add(self.bottom_frame, weight=2) # Bottom gets 2 parts height
        
        # The actual notebook (Always packed to prevent UI jumps)
        self.detail_notebook = tb.Notebook(self.bottom_frame)
        self.detail_notebook.pack(fill=BOTH, expand=True)
        self.detail_notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        self.summary_tab = tb.Frame(self.detail_notebook, padding="15")
        self.detail_notebook.add(self.summary_tab, text="Summary")
        self.no_host_label = tb.Label(self.summary_tab, text="Select a host from the table above to view details and launch attacks.", font=("Helvetica", 14), foreground="gray", justify=CENTER)
        self.no_host_label.pack(expand=True)
        
        self.ports_tab = tb.Frame(self.detail_notebook, padding="15")
        self.detail_notebook.add(self.ports_tab, text="Port Scanner", state="disabled")
        
        self.arp_tab = tb.Frame(self.detail_notebook, padding="15")
        self.detail_notebook.add(self.arp_tab, text="ARP Poisoning", state="disabled")
        
        self.dos_tab = tb.Frame(self.detail_notebook, padding="15")
        self.detail_notebook.add(self.dos_tab, text="Denial of Service", state="disabled")
        
        self.trace_tab = tb.Frame(self.detail_notebook, padding="15")
        self.detail_notebook.add(self.trace_tab, text="Traceroute", state="disabled")
        
        self.setup_ports_ui()
        self.setup_arp_ui()
        self.setup_dos_ui()
        self.setup_trace_ui()
        
    def setup_master_view(self) -> None:
        """
        Sets up the top frame containing scan controls and the host table.
        :return: None
        """
        # Controls Frame
        controls_frame = tb.Frame(self.top_frame)
        controls_frame.pack(fill=X, pady=(0, 10))
        
        # Row 0
        tb.Label(controls_frame, text="Interface:", font=("Helvetica", 10)).grid(row=0, column=0, sticky=W, padx=(0,5), pady=5)
        self.iface_combo = tb.Combobox(controls_frame, values=list(self.interfaces.keys()), state="readonly", width=30, bootstyle=PRIMARY)
        self.iface_combo.grid(row=0, column=1, sticky=W, padx=(0, 15), pady=5)
        self.iface_combo.bind("<<ComboboxSelected>>", self.on_iface_changed)
        
        tb.Label(controls_frame, text="IP Range:", font=("Helvetica", 10)).grid(row=0, column=2, sticky=W, padx=(0,5), pady=5)
        self.ip_entry = tb.Entry(controls_frame, width=20)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=3, sticky=W, padx=(0, 15), pady=5)
        
        # Row 1
        self.scan_ports_var = tb.BooleanVar(value=False)
        self.scan_ports_check = tb.Checkbutton(controls_frame, text="Scan Ports", variable=self.scan_ports_var, bootstyle="round-toggle", command=self.toggle_port_range_ui)
        self.scan_ports_check.grid(row=1, column=0, sticky=W, padx=(0, 15), pady=5)
        
        self.port_range_frame = tb.Frame(controls_frame)
        self.port_range_frame.grid(row=1, column=1, columnspan=2, sticky=W)
        
        tb.Label(self.port_range_frame, text="Range:", font=("Helvetica", 10)).pack(side=LEFT, padx=(0,5))
        self.port_entry = tb.Entry(self.port_range_frame, width=12)
        self.port_entry.insert(0, "20-1000")
        self.port_entry.pack(side=LEFT, padx=(0, 15))
        self.port_range_frame.grid_remove() # Hidden initially
        
        # Scan Button
        self.scan_btn = tb.Button(controls_frame, text="Start Scan", command=self.start_host_scan, bootstyle=SUCCESS)
        self.scan_btn.grid(row=1, column=3, sticky=W, pady=5)
        
        self.scan_progress = tb.Progressbar(self.top_frame, mode='indeterminate', bootstyle=SUCCESS)
        # Packed when scanning starts
        
        # Host Table Frame
        table_frame = tb.Frame(self.top_frame)
        table_frame.pack(fill=BOTH, expand=True, pady=(5, 0))
        
        columns = ("ip", "mac", "os", "ports")
        self.host_tree = tb.Treeview(table_frame, columns=columns, show="headings", bootstyle=INFO, selectmode="browse")
        self.host_tree.heading("ip", text="IP Address")
        self.host_tree.heading("mac", text="MAC Address")
        self.host_tree.heading("os", text="OS Guess")
        self.host_tree.heading("ports", text="Open Ports Summary")
        
        self.host_tree.column("ip", width=120)
        self.host_tree.column("mac", width=150)
        self.host_tree.column("os", width=150)
        self.host_tree.column("ports", width=200)
        
        scroll = tb.Scrollbar(table_frame, orient=VERTICAL, command=self.host_tree.yview, bootstyle=ROUND)
        self.host_tree.configure(yscrollcommand=scroll.set)
        
        self.host_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)
        
        # Bind row selection
        self.host_tree.bind("<<TreeviewSelect>>", self.on_host_selected)
        
        self.discovered_hosts: List[models.Host] = [] # Store host objects

    def toggle_port_range_ui(self) -> None:
        """
        Toggles the visibility of the port range input based on the port scan checkbox.
        :return: None
        """
        if self.scan_ports_var.get():
            self.port_range_frame.grid()
        else:
            self.port_range_frame.grid_remove()

    def on_iface_changed(self, event: Optional[Any] = None) -> None:
        """
        Callback triggered when the network interface selection changes.
        :param event: Optional event object
        :return: None
        """
        # Attempt to auto-update gateway IP on interface switch
        gw = get_gateway()
        if gw and hasattr(self, 'gw_ip_entry'):
            self.gw_ip_entry.delete(0, END)
            self.gw_ip_entry.insert(0, gw)

    def start_host_scan(self) -> None:
        """
        Starts the network host discovery scan process.
        :return: None
        """
        friendly_iface = self.iface_combo.get()
        if not friendly_iface:
            messagebox.showerror("Error", "Please select an interface.")
            return
            
        real_iface = self.interfaces[friendly_iface]
        ip_range = self.ip_entry.get().strip()
        do_port_scan = self.scan_ports_var.get()
        port_range = self.port_entry.get().strip() if do_port_scan else None
        
        if not ip_range:
            messagebox.showerror("Error", "Please enter an IP range.")
            return
            
        self.scan_btn.config(state=DISABLED, text="Scanning...")
        self.scan_progress.pack(fill=X, pady=(0, 5))
        self.scan_progress.start(10)
        
        # Clear table
        for item in self.host_tree.get_children():
            self.host_tree.delete(item)
        self.discovered_hosts = []
        
        # Deselect host & update notebook
        self.active_host = None
        self.detail_notebook.tab(self.ports_tab, state="disabled")
        self.detail_notebook.tab(self.arp_tab, state="disabled")
        self.detail_notebook.tab(self.dos_tab, state="disabled")
        self.detail_notebook.tab(self.trace_tab, state="disabled")
        self.detail_notebook.select(self.summary_tab)
        self.no_host_label.config(text="Select a host from the table above to view details and launch attacks.", foreground="gray")
        
        threading.Thread(target=self.run_scan, args=(real_iface, ip_range, do_port_scan, port_range), daemon=True).start()
        
    def run_scan(self, iface: str, ip_range: str, do_port_scan: bool, port_range: Optional[str]) -> None:
        """
        Executes the network scan in a background thread.
        :param iface: The network interface to use
        :param ip_range: The IP range to scan
        :param do_port_scan: Whether to perform a port scan
        :param port_range: The port range string to scan
        :return: None
        """
        try:
            port_r: Optional[Union[int, Tuple[int, int]]] = None
            if do_port_scan and port_range:
                if '-' in port_range:
                    start, end = map(int, port_range.split('-'))
                    port_r = (start, end)
                else:
                    port_r = int(port_range)
                    
            scanner_obj = NetworkScanner(ip_range=ip_range, port_range=port_r, iface=iface)
            scanner_obj.discover_hosts()
            
            if do_port_scan and port_r is not None:
                for host in scanner_obj.hosts:
                    scanner_obj.scan_ports(host)
                    
            self.after(0, self.on_scan_complete, scanner_obj.hosts)
        except Exception as e:
            self.after(0, self.on_scan_error, str(e))
            
    def on_scan_complete(self, hosts: List[models.Host]) -> None:
        """
        Callback triggered when the network scan is finished.
        :param hosts: List of discovered Host objects
        :return: None
        """
        self.scan_progress.stop()
        self.scan_progress.pack_forget()
        self.scan_btn.config(state=NORMAL, text="Start Scan")
        self.discovered_hosts = hosts
        
        if not hosts:
            messagebox.showinfo("Scan Complete", "No hosts found in the specified range.")
            return
            
        for i, host in enumerate(hosts):
            open_ports_count = len([p for p in host.ports if p.status == "open"])
            port_summary = f"{open_ports_count} open ports" if open_ports_count > 0 else "None found/Scanned"
            os_guess = host.os if host.os else "Unknown"
            
            self.host_tree.insert("", END, iid=str(i), values=(host.ip_address, host.mac_address, os_guess, port_summary))

    def on_scan_error(self, err_msg: str) -> None:
        """
        Callback triggered if an error occurs during the network scan.
        :param err_msg: The error message
        :return: None
        """
        self.scan_progress.stop()
        self.scan_progress.pack_forget()
        self.scan_btn.config(state=NORMAL, text="Start Scan")
        messagebox.showerror("Scan Error", f"An error occurred during scan:\n{err_msg}")

    def on_host_selected(self, event: Any) -> None:
        """
        Callback triggered when a host is selected in the host table.
        :param event: The selection event
        :return: None
        """
        selected_items = self.host_tree.selection()
        if not selected_items:
            return
            
        # We explicitly DO NOT stop attacks here to maintain backend state stability.
            
        idx = int(selected_items[0])
        self.active_host = self.discovered_hosts[idx]
        
        self.no_host_label.config(text=f"Selected Host:\nIP: {self.active_host.ip_address}\nMAC: {self.active_host.mac_address}", foreground="white")
        
        # Enable Notebook Tabs
        self.detail_notebook.tab(self.ports_tab, state="normal")
        self.detail_notebook.tab(self.arp_tab, state="normal")
        self.detail_notebook.tab(self.dos_tab, state="normal")
        self.detail_notebook.tab(self.trace_tab, state="normal")
        
        # Mark ports as needing refresh but only refresh if the tab is visible
        self.ports_need_refresh = True
        if self.is_ports_tab_visible():
            self.refresh_ports_tab()
        
        # Pre-fill trace target
        self.trace_target_entry.delete(0, END)
        self.trace_target_entry.insert(0, self.active_host.ip_address)

    def on_tab_changed(self, event: Optional[Any] = None) -> None:
        """
        Callback triggered when the active tab in the detail notebook changes.
        :param event: Optional event object
        :return: None
        """
        if self.is_ports_tab_visible() and self.ports_need_refresh:
            self.refresh_ports_tab()

    def is_ports_tab_visible(self) -> bool:
        """
        Checks if the Port Scanner tab is currently selected.
        :return: True if visible, False otherwise
        """
        try:
            return self.detail_notebook.tab(self.detail_notebook.select(), "text") == "Port Scanner"
        except:
            return False

    # --- PORT SCANNER UI ---
    def setup_ports_ui(self) -> None:
        """
        Sets up the UI components for the Port Scanner tab.
        :return: None
        """
        top_frame = tb.Frame(self.ports_tab)
        top_frame.pack(fill=X, pady=(0, 15))
        
        tb.Label(top_frame, text="Port Range:", font=("Helvetica", 11)).grid(row=0, column=0, sticky=W, padx=(0, 5), pady=5)
        self.detail_port_entry = tb.Entry(top_frame, width=15)
        self.detail_port_entry.insert(0, "20-1000")
        self.detail_port_entry.grid(row=0, column=1, sticky=W, padx=(0, 15), pady=5)
        
        self.target_scan_btn = tb.Button(top_frame, text="Scan Target Ports", command=self.scan_target_ports, bootstyle=SUCCESS)
        self.target_scan_btn.grid(row=0, column=2, sticky=W, padx=(0, 15), pady=5)
        
        tb.Label(top_frame, text="Status Filter:", font=("Helvetica", 11)).grid(row=1, column=0, sticky=W, padx=(0, 5), pady=5)
        self.status_filter_var = tb.StringVar(value="open")
        self.status_combo = tb.Combobox(top_frame, textvariable=self.status_filter_var, values=["All", "open", "closed", "filtered", "open|filtered"], state="readonly", width=12, bootstyle=PRIMARY)
        self.status_combo.grid(row=1, column=1, sticky=W, pady=5)
        self.status_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_ports_tab())

        tb.Label(top_frame, text="Proto Filter:", font=("Helvetica", 11)).grid(row=1, column=2, sticky=W, padx=(0, 5), pady=5)
        self.proto_filter_var = tb.StringVar(value="All")
        self.proto_combo = tb.Combobox(top_frame, textvariable=self.proto_filter_var, values=["All", "TCP", "UDP"], state="readonly", width=10, bootstyle=PRIMARY)
        self.proto_combo.grid(row=1, column=3, sticky=W, pady=5)
        self.proto_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_ports_tab())
        
        self.port_progress = tb.Progressbar(self.ports_tab, mode='indeterminate', bootstyle=INFO)
        
        # Results Tree
        columns = ("Port", "Proto", "Status", "Service")
        self.port_tree = tb.Treeview(self.ports_tab, columns=columns, show="headings", bootstyle=INFO)
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=120, anchor=CENTER)
            
        scroll = tb.Scrollbar(self.ports_tab, orient=VERTICAL, command=self.port_tree.yview, bootstyle=ROUND)
        self.port_tree.configure(yscrollcommand=scroll.set)
        
        self.port_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)

    def refresh_ports_tab(self) -> None:
        """
        Refreshes the port results table based on active filters.
        :return: None
        """
        if not self.active_host:
            return
            
        self.ports_need_refresh = False
        
        # Clear existing items
        self.port_tree.delete(*self.port_tree.get_children())
            
        filter_status = self.status_filter_var.get().lower()
        filter_proto = self.proto_filter_var.get().lower()

        for port in self.active_host.ports:
            # Protocol filter
            if filter_proto != "all" and port.proto != filter_proto:
                continue
            
            # General view (no proto filter) -> hide "open|filtered" UDP ports
            # Unless explicitly requested by the status filter
            if filter_proto == "all" and port.proto == "udp" and port.status == "open|filtered":
                if filter_status != "open|filtered":
                    continue

            # Status filter
            port_status_lower = port.status.lower()
            if filter_status != "all":
                # Exact match for open/closed to avoid partial matches like "open" in "open|filtered"
                if filter_status in ["open", "closed"]:
                    if port_status_lower != filter_status:
                        continue
                elif filter_status not in port_status_lower:
                    continue
                
            self.port_tree.insert("", END, values=(port.port_number, port.proto.upper() if port.proto else "N/A", port.status, port.service))
                
    def scan_target_ports(self) -> None:
        """
        Initiates a port scan on the currently selected host.
        :return: None
        """
        if not self.active_host: return
        
        port_range_str = self.detail_port_entry.get().strip()
        try:
            if '-' in port_range_str:
                start, end = map(int, port_range_str.split('-'))
                port_range = (start, end)
            else:
                port_range = int(port_range_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid port range format. Use a number or 'start-end'.")
            return
            
        self.target_scan_btn.config(state=DISABLED, text="Scanning...")
        self.port_progress.pack(fill=X, pady=(0, 10), before=self.port_tree)
        self.port_progress.start(10)
        
        self.active_host.ports = []
        self.refresh_ports_tab()
        
        friendly_iface = self.iface_combo.get()
        real_iface = self.interfaces[friendly_iface]
        
        threading.Thread(target=self._run_target_port_scan, args=(port_range, real_iface), daemon=True).start()
        
    def _run_target_port_scan(self, port_range: Union[int, Tuple[int, int]], iface: str) -> None:
        """
        Background task to perform the port scan on a specific host.
        :param port_range: The port range to scan
        :param iface: The network interface to use
        :return: None
        """
        try:
            if self.active_host is None:
                return
            scanner_obj = NetworkScanner(ip_range=self.active_host.ip_address, port_range=port_range, iface=iface)
            scanner_obj.scan_ports(self.active_host)
            self.after(0, self._on_target_port_scan_complete)
        except Exception as e:
            self.after(0, self._on_target_port_scan_error, str(e))
            
    def _on_target_port_scan_complete(self) -> None:
        """
        Callback triggered when a host-specific port scan is finished.
        :return: None
        """
        self.port_progress.stop()
        self.port_progress.pack_forget()
        self.target_scan_btn.config(state=NORMAL, text="Scan Target Ports")
        self.refresh_ports_tab()
        
        # update master table summary
        if self.active_host:
            for item in self.host_tree.get_children():
                vals = self.host_tree.item(item, 'values')
                if vals[0] == self.active_host.ip_address:
                    open_ports_count = len([p for p in self.active_host.ports if p.status == "open"])
                    port_summary = f"{open_ports_count} open ports" if open_ports_count > 0 else "None found"
                    # update just the port summary column
                    self.host_tree.set(item, column="ports", value=port_summary)
                    if self.active_host.os:
                         self.host_tree.set(item, column="os", value=self.active_host.os)
                    break

        if self.active_host and not self.active_host.ports:
            messagebox.showinfo("Scan Complete", "No open ports found.")

    def _on_target_port_scan_error(self, err: str) -> None:
        """
        Callback triggered if an error occurs during a host-specific port scan.
        :param err: The error message
        :return: None
        """
        self.port_progress.stop()
        self.port_progress.pack_forget()
        self.target_scan_btn.config(state=NORMAL, text="Scan Target Ports")
        messagebox.showerror("Error", err)

    # --- ARP POISONING UI ---
    def setup_arp_ui(self) -> None:
        """
        Sets up the UI components for the ARP Poisoning tab.
        :return: None
        """
        input_frame = tb.Frame(self.arp_tab)
        input_frame.pack(fill=X, pady=(0, 15))
        
        tb.Label(input_frame, text="Gateway IP:").grid(row=0, column=0, sticky=W, pady=5)
        self.gw_ip_entry = tb.Entry(input_frame, width=30)
        gw = get_gateway()
        if gw:
            self.gw_ip_entry.insert(0, gw)
        self.gw_ip_entry.grid(row=0, column=1, sticky=W, pady=5, padx=15)
        
        flags_frame = tb.Labelframe(self.arp_tab, text="Attack Options", padding="15", bootstyle=WARNING)
        flags_frame.pack(fill=X, pady=15)
        
        self.do_save_var = tb.BooleanVar(value=False)
        tb.Checkbutton(flags_frame, text="Save intercepted traffic to PCAP", variable=self.do_save_var, bootstyle="round-toggle").pack(anchor=W, pady=5)
        
        self.dns_spoof_var = tb.BooleanVar(value=False)
        tb.Checkbutton(flags_frame, text="Enable DNS Spoofing", variable=self.dns_spoof_var, command=self.toggle_dns_spoof, bootstyle="round-toggle").pack(anchor=W, pady=5)
        
        self.dns_frame = tb.Frame(flags_frame)
        tb.Label(self.dns_frame, text="Domain to redirect from:").grid(row=0, column=0, sticky=W, pady=5)
        self.orig_domain_entry = tb.Entry(self.dns_frame, width=30)
        self.orig_domain_entry.grid(row=0, column=1, sticky=W, pady=5, padx=10)
        
        tb.Label(self.dns_frame, text="Domain/IP to redirect to:").grid(row=1, column=0, sticky=W, pady=5)
        self.spoofed_ip_entry = tb.Entry(self.dns_frame, width=30)
        self.spoofed_ip_entry.grid(row=1, column=1, sticky=W, pady=5, padx=10)
        
        ctrl_frame = tb.Frame(self.arp_tab)
        ctrl_frame.pack(fill=X, pady=25)
        
        self.arp_start_btn = tb.Button(ctrl_frame, text="Start MiTM Attack", command=self.start_arp_attack, bootstyle=DANGER)
        self.arp_start_btn.pack(side=LEFT, padx=(0, 15), ipadx=10, ipady=5)
        
        self.arp_stop_btn = tb.Button(ctrl_frame, text="Stop Attack", command=self.stop_arp_attack, state=DISABLED, bootstyle=SECONDARY)
        self.arp_stop_btn.pack(side=LEFT, ipadx=10, ipady=5)
        
        self.arp_status_lbl = tb.Label(self.arp_tab, text="Status: Ready", font=("Helvetica", 11, "bold"), bootstyle=SUCCESS)
        self.arp_status_lbl.pack(anchor=W, pady=15)

    def toggle_dns_spoof(self) -> None:
        """
        Toggles the visibility of DNS spoofing input fields.
        :return: None
        """
        if self.dns_spoof_var.get():
            self.dns_frame.pack(fill=X, pady=(15, 0))
        else:
            self.dns_frame.pack_forget()

    def start_arp_attack(self) -> None:
        """
        Initiates the ARP poisoning attack.
        :return: None
        """
        if self.arp_attack and self.arp_attack.is_running:
            messagebox.showerror("Error", "An ARP attack is already running. Please stop it before starting a new one.")
            return
            
        if not self.active_host: return
        
        gw_ip = self.gw_ip_entry.get().strip()
        if not is_valid_ip(gw_ip):
            messagebox.showerror("Error", "A valid Gateway IP is required.")
            return
            
        do_save = self.do_save_var.get()
        redirect_to = self.spoofed_ip_entry.get().strip() if self.dns_spoof_var.get() else None
        orig_domain = self.orig_domain_entry.get().strip() if self.dns_spoof_var.get() else None
        
        if self.dns_spoof_var.get() and (not redirect_to or not orig_domain):
            messagebox.showerror("Error", "Domain to redirect from and Domain/IP to redirect to are required for DNS spoofing.")
            return
            
        self.arp_start_btn.config(state=DISABLED)
        self.arp_status_lbl.config(text="Status: Starting Attack...", bootstyle=WARNING)
        
        friendly_iface = self.iface_combo.get()
        real_iface = self.interfaces[friendly_iface]
        
        threading.Thread(target=self._init_and_start_arp, args=(gw_ip, real_iface, do_save, redirect_to, orig_domain), daemon=True).start()

    def _init_and_start_arp(self, gw_ip: str, iface: str, do_save: bool, redirect_to: Optional[str], orig_domain: Optional[str]) -> None:
        """
        Background task to resolve addresses and start the ARP poisoning attack.
        :param gw_ip: Gateway IP address
        :param iface: Network interface to use
        :param do_save: Whether to save pcap
        :param redirect_to: Optional redirect target for DNS spoofing
        :param orig_domain: Optional domain to spoof
        :return: None
        """
        try:
            spoofed_ip = None
            if redirect_to:
                if not is_valid_ip(redirect_to):
                    resolved_ip = TraceScanner.resolve_hostname(redirect_to)
                    if not resolved_ip:
                        self.after(0, self._on_arp_error, f"Could not resolve domain: {redirect_to}")
                        return
                    spoofed_ip = resolved_ip
                else:
                    spoofed_ip = redirect_to

            gw_mac = get_mac_by_ip(gw_ip, iface)
            if not gw_mac:
                self.after(0, self._on_arp_error, "Failed to resolve Gateway MAC.")
                return
                
            gateway = models.Host(ip_address=gw_ip, mac_address=gw_mac)
            if self.active_host is None:
                return
            self.arp_attack = ArpPoisoning(self.active_host, gateway, iface, do_save, spoofed_ip, orig_domain)
            self.arp_attack.start()
            
            self.after(0, self._on_arp_started)
        except Exception as e:
            self.after(0, self._on_arp_error, str(e))
            
    def _on_arp_started(self) -> None:
        """
        Callback triggered when the ARP attack has successfully started.
        :return: None
        """
        self.arp_stop_btn.config(state=NORMAL)
        if self.active_host:
            self.arp_status_lbl.config(text=f"Status: Active on {self.active_host.ip_address}", bootstyle=DANGER)
        
    def _on_arp_error(self, err: str) -> None:
        """
        Callback triggered if an error occurs while starting the ARP attack.
        :param err: The error message
        :return: None
        """
        self.arp_start_btn.config(state=NORMAL)
        self.arp_status_lbl.config(text=f"Status: Error - {err}", bootstyle=DANGER)
        
    def stop_arp_attack(self) -> None:
        """
        Initiates the process to stop the active ARP attack.
        :return: None
        """
        if self.arp_attack:
            self.arp_stop_btn.config(state=DISABLED)
            self.arp_status_lbl.config(text="Status: Stopping & Restoring Tables...", bootstyle=WARNING)
            threading.Thread(target=self._stop_arp_thread, daemon=True).start()
            
    def _stop_arp_thread(self) -> None:
        """
        Background task to stop the ARP attack and restore tables.
        :return: None
        """
        try:
            if self.arp_attack:
                self.arp_attack.stop()
        except Exception:
            pass
        self.after(0, self._on_arp_stopped)
        
    def _on_arp_stopped(self) -> None:
        """
        Callback triggered when the ARP attack has successfully stopped.
        :return: None
        """
        self.arp_attack = None
        self.arp_start_btn.config(state=NORMAL)
        self.arp_status_lbl.config(text="Status: Stopped & Restored", bootstyle=SUCCESS)

    # --- DOS UI ---
    def setup_dos_ui(self) -> None:
        """
        Sets up the UI components for the Denial of Service tab.
        :return: None
        """
        st_frame = tb.Labelframe(self.dos_tab, text="Single Target DoS (ARP Blackhole)", padding="15", bootstyle=DANGER)
        st_frame.pack(fill=X, pady=(0, 20))
        tb.Label(st_frame, text="Cuts off the active target from the gateway by poisoning both with dummy MACs.").pack(anchor=W, pady=(0, 15))
        
        st_btn_frame = tb.Frame(st_frame)
        st_btn_frame.pack(fill=X)
        self.st_dos_start_btn = tb.Button(st_btn_frame, text="Start Target DoS", command=self.start_st_dos, bootstyle=DANGER)
        self.st_dos_start_btn.grid(row=0, column=0, padx=(0, 15), pady=5, ipadx=5, ipady=5)
        self.st_dos_stop_btn = tb.Button(st_btn_frame, text="Stop Target DoS", command=self.stop_st_dos, state=DISABLED, bootstyle=SECONDARY)
        self.st_dos_stop_btn.grid(row=0, column=1, pady=5, ipadx=5, ipady=5)
        
        self.st_dos_status_lbl = tb.Label(st_frame, text="Status: Ready", bootstyle=SUCCESS, font=("Helvetica", 10, "bold"))
        self.st_dos_status_lbl.pack(anchor=W, pady=10)
        
        dhcp_frame = tb.Labelframe(self.dos_tab, text="DHCP Starvation (Network-Wide)", padding="15", bootstyle=DANGER)
        dhcp_frame.pack(fill=X)
        
        warning_lbl = tb.Label(dhcp_frame, text="WARNING: Floods the network with DHCP requests, exhausting the pool for ALL devices.", bootstyle=WARNING, wraplength=400)
        warning_lbl.pack(anchor=W, pady=(0, 15), fill=X)
        
        dhcp_btn_frame = tb.Frame(dhcp_frame)
        dhcp_btn_frame.pack(fill=X)
        self.dhcp_start_btn = tb.Button(dhcp_btn_frame, text="Start DHCP Starvation", command=self.start_dhcp, bootstyle=DANGER)
        self.dhcp_start_btn.grid(row=0, column=0, padx=(0, 10), pady=5, ipadx=5, ipady=5)
        self.dhcp_stop_btn = tb.Button(dhcp_btn_frame, text="Stop DHCP Starvation", command=self.stop_dhcp, state=DISABLED, bootstyle=SECONDARY)
        self.dhcp_stop_btn.grid(row=0, column=1, pady=5, ipadx=5, ipady=5)
        
        self.dhcp_status_lbl = tb.Label(dhcp_frame, text="Status: Ready", bootstyle=SUCCESS, font=("Helvetica", 10, "bold"))
        self.dhcp_status_lbl.pack(anchor=W, pady=(10, 0))

    def start_st_dos(self) -> None:
        """
        Initiates the single target DoS attack.
        :return: None
        """
        if self.st_dos_attack and self.st_dos_attack.is_running:
            messagebox.showerror("Error", "A Single Target DoS attack is already running. Please stop it first.")
            return

        if not self.active_host: return
        gw_ip = get_gateway()
        if not is_valid_ip(gw_ip):
            messagebox.showerror("Error", "Could not detect a valid gateway IP automatically.")
            return
            
        self.st_dos_start_btn.config(state=DISABLED)
        self.st_dos_status_lbl.config(text="Status: Resolving Gateway...", bootstyle=WARNING)
        
        friendly_iface = self.iface_combo.get()
        real_iface = self.interfaces[friendly_iface]
        
        threading.Thread(target=self._init_st_dos, args=(gw_ip, real_iface), daemon=True).start()
        
    def _init_st_dos(self, gw_ip: str, iface: str) -> None:
        """
        Background task to resolve addresses and start the single target DoS attack.
        :param gw_ip: Gateway IP address
        :param iface: Network interface to use
        :return: None
        """
        try:
            gw_mac = get_mac_by_ip(gw_ip, iface)
            if not gw_mac:
                self.after(0, self._on_st_dos_error, "Could not resolve Gateway MAC.")
                return
            if self.active_host is None:
                return
            self.st_dos_attack = SingleTargetDos(self.active_host, gw_ip, gw_mac, iface)
            self.st_dos_attack.start()
            self.after(0, self._on_st_dos_started)
        except Exception as e:
            self.after(0, self._on_st_dos_error, str(e))
            
    def _on_st_dos_started(self) -> None:
        """
        Callback triggered when the single target DoS attack has started.
        :return: None
        """
        self.st_dos_stop_btn.config(state=NORMAL)
        if self.active_host:
            self.st_dos_status_lbl.config(text=f"Status: Active on {self.active_host.ip_address}", bootstyle=DANGER)
        
    def _on_st_dos_error(self, err: str) -> None:
        """
        Callback triggered if an error occurs while starting the DoS attack.
        :param err: The error message
        :return: None
        """
        self.st_dos_start_btn.config(state=NORMAL)
        self.st_dos_status_lbl.config(text=f"Status: Error - {err}", bootstyle=DANGER)
        
    def stop_st_dos(self) -> None:
        """
        Initiates the process to stop the active single target DoS attack.
        :return: None
        """
        if self.st_dos_attack:
            self.st_dos_stop_btn.config(state=DISABLED)
            self.st_dos_status_lbl.config(text="Status: Stopping...", bootstyle=WARNING)
            threading.Thread(target=self._stop_st_dos_thread, daemon=True).start()
            
    def _stop_st_dos_thread(self) -> None:
        """
        Background task to stop the DoS attack.
        :return: None
        """
        if self.st_dos_attack:
            self.st_dos_attack.stop()
        self.after(0, self._on_st_dos_stopped)
        
    def _on_st_dos_stopped(self) -> None:
        """
        Callback triggered when the DoS attack has stopped.
        :return: None
        """
        self.st_dos_attack = None
        self.st_dos_start_btn.config(state=NORMAL)
        self.st_dos_status_lbl.config(text="Status: Stopped", bootstyle=SUCCESS)

    def start_dhcp(self) -> None:
        """
        Starts the DHCP starvation attack.
        :return: None
        """
        if self.dhcp_attack and self.dhcp_attack.is_running:
            return

        self.dhcp_start_btn.config(state=DISABLED)
        self.dhcp_stop_btn.config(state=NORMAL)
        self.dhcp_status_lbl.config(text="Status: Active (Starving DHCP pool)", bootstyle=DANGER)
        
        friendly_iface = self.iface_combo.get()
        real_iface = self.interfaces[friendly_iface]
        
        self.dhcp_attack = DHCPStarvation(iface=real_iface)
        self.dhcp_attack.start()
        
    def stop_dhcp(self) -> None:
        """
        Initiates the process to stop the DHCP starvation attack.
        :return: None
        """
        if self.dhcp_attack:
            self.dhcp_stop_btn.config(state=DISABLED)
            self.dhcp_status_lbl.config(text="Status: Stopping...", bootstyle=WARNING)
            threading.Thread(target=self._stop_dhcp_thread, daemon=True).start()
            
    def _stop_dhcp_thread(self) -> None:
        """
        Background task to stop the DHCP starvation attack.
        :return: None
        """
        if self.dhcp_attack:
            self.dhcp_attack.stop()
        self.after(0, self._on_dhcp_stopped)
        
    def _on_dhcp_stopped(self) -> None:
        """
        Callback triggered when the DHCP starvation attack has stopped.
        :return: None
        """
        self.dhcp_attack = None
        self.dhcp_start_btn.config(state=NORMAL)
        self.dhcp_status_lbl.config(text="Status: Stopped", bootstyle=SUCCESS)

    # --- GLOBAL TRACEROUTE UI ---
    def setup_trace_ui(self) -> None:
        """
        Sets up the UI components for the Traceroute tab.
        :return: None
        """
        top_frame = tb.Frame(self.trace_tab)
        top_frame.pack(fill=X, pady=(0, 15))
        
        tb.Label(top_frame, text="Target IP/Domain:", font=("Helvetica", 11)).grid(row=0, column=0, sticky=W, padx=(0, 5), pady=5)
        self.trace_target_entry = tb.Entry(top_frame, width=25)
        # Prefilled in on_host_selected
        self.trace_target_entry.grid(row=0, column=1, sticky=W, padx=(0, 15), pady=5)
        
        tb.Label(top_frame, text="Max Hops:", font=("Helvetica", 11)).grid(row=0, column=2, sticky=W, padx=(0, 5), pady=5)
        self.hops_entry = tb.Entry(top_frame, width=8)
        self.hops_entry.insert(0, "30")
        self.hops_entry.grid(row=0, column=3, sticky=W, padx=(0, 15), pady=5)
        
        self.trace_btn = tb.Button(top_frame, text="Start Trace", command=self.start_trace, bootstyle=PRIMARY)
        self.trace_btn.grid(row=0, column=4, sticky=W, pady=5)
        
        self.trace_progress = tb.Progressbar(self.trace_tab, mode='indeterminate', bootstyle=PRIMARY)
        
        # Results Tree
        columns = ("Hop", "IP Address", "Time")
        self.trace_tree = tb.Treeview(self.trace_tab, columns=columns, show="headings", bootstyle=PRIMARY)
        for col in columns:
            self.trace_tree.heading(col, text=col)
            
        self.trace_tree.column("Hop", width=80, anchor=CENTER)
        self.trace_tree.column("IP Address", width=300, anchor=W)
        self.trace_tree.column("Time", width=150, anchor=W)
            
        scroll = tb.Scrollbar(self.trace_tab, orient=VERTICAL, command=self.trace_tree.yview, bootstyle=ROUND)
        self.trace_tree.configure(yscrollcommand=scroll.set)
        
        self.trace_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)

    def start_trace(self) -> None:
        """
        Initiates the traceroute process.
        :return: None
        """
        target = self.trace_target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Target cannot be empty.")
            return
            
        try:
            max_hops = int(self.hops_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Max hops must be a valid integer.")
            return
            
        self.trace_btn.config(state=DISABLED, text="Tracing...")
        self.trace_progress.pack(fill=X, pady=(0, 10), before=self.trace_tree)
        self.trace_progress.start(10)
        
        for item in self.trace_tree.get_children():
            self.trace_tree.delete(item)
            
        threading.Thread(target=self._run_trace, args=(target, max_hops), daemon=True).start()
        
    def _run_trace(self, target: str, max_hops: int) -> None:
        """
        Background task to execute the traceroute.
        :param target: The target IP or hostname
        :param max_hops: Maximum number of hops
        :return: None
        """
        try:
            target_ip = target
            if not is_valid_ip(target):
                resolved_ip = TraceScanner.resolve_hostname(target)
                if not resolved_ip:
                    self.after(0, self._on_trace_error, f"Could not resolve hostname: {target}")
                    return
                target_ip = resolved_ip
                
            scanner_obj = TraceScanner(target_ip=target_ip, max_hops=max_hops)
            scanner_obj.start()
            self.after(0, self._on_trace_complete, scanner_obj.path)
        except Exception as e:
            self.after(0, self._on_trace_error, str(e))
            
    def _on_trace_complete(self, path: List[Dict[str, Any]]) -> None:
        """
        Callback triggered when the traceroute is complete.
        :param path: List of hop data dictionaries
        :return: None
        """
        self.trace_progress.stop()
        self.trace_progress.pack_forget()
        self.trace_btn.config(state=NORMAL, text="Start Trace")
        
        for hop in path:
            self.trace_tree.insert("", END, values=(hop['hop'], hop['ip'], hop['time']))
        
    def _on_trace_error(self, err: str) -> None:
        """
        Callback triggered if an error occurs during traceroute.
        :param err: The error message
        :return: None
        """
        self.trace_progress.stop()
        self.trace_progress.pack_forget()
        self.trace_btn.config(state=NORMAL, text="Start Trace")
        messagebox.showerror("Trace Error", f"An error occurred during traceroute:\n{err}")


if __name__ == "__main__":
    gui_app = NetworkMapperGUI()
    gui_app.mainloop()
