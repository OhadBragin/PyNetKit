<div id="top">

<!-- HEADER STYLE: CONSOLE -->
<div align="center">

```console
██████╗ ██╗   ██╗███╗   ██╗███████╗████████╗██╗  ██╗██╗████████╗
██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
██████╔╝ ╚████╔╝ ██╔██╗ ██║█████╗     ██║   █████╔╝ ██║   ██║   
██╔═══╝   ╚██╔╝  ██║╚██╗██║██╔══╝     ██║   ██╔═██╗ ██║   ██║   
██║        ██║   ██║ ╚████║███████╗   ██║   ██║  ██╗██║   ██║   
╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝   
```

*A dual-interface network mapper and security auditing toolkit.*

</div>

<img src="https://img.shields.io/badge/TOML-9C4121.svg?style=for-the-badge&logo=TOML&logoColor=white" alt="TOML">
<img src="https://img.shields.io/badge/Rich-FAE742.svg?style=for-the-badge&logo=Rich&logoColor=black" alt="Rich">
<img src="https://img.shields.io/badge/Pytest-0A9EDC.svg?style=for-the-badge&logo=Pytest&logoColor=white" alt="Pytest">
<img src="https://img.shields.io/badge/Python-3776AB.svg?style=for-the-badge&logo=Python&logoColor=white" alt="Python">

---

> 🚨
> **Legal Disclaimer**
>
> PyNetKit is intended strictly for **educational purposes** and **authorized network auditing** on networks you own or have explicit written permission to test. Running any of these tools against networks or systems without mutual consent is **illegal** and may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, or equivalent laws in your jurisdiction. **The author assumes no liability** for any misuse, damage, or legal consequences arising from the use of this software. Use responsibly.

---

<br>

## ⚛️ Table of Contents

<details>
<summary>Table of Contents</summary>

- [⚛️ Table of Contents](#️-table-of-contents)
- [🔮 Overview](#-overview)
- [💫 Features](#-features)
- [🌌 Project Structure](#-project-structure)
    - [✨ Project Index](#-project-index)
- [⚡ Getting Started](#-getting-started)
    - [💠 Prerequisites](#-prerequisites)
    - [🔷 Installation](#-installation)
    - [🔹 Usage](#-usage)
    - [🔸 Testing](#-testing)
- [🤖 AI Transparency](#-ai-transparency)
- [⭐ License](#-license)

</details>

---

## 🔮 Overview

PyNetKit is a network discovery and security auditing toolkit with a **dual interface**: a terminal-first CLI powered by [Rich](https://github.com/Textualize/rich) and a full graphical GUI built with [ttkbootstrap](https://ttkbootstrap.readthedocs.io/). Both surfaces expose the same feature set, so you can choose the workflow that fits the task.

All packet-level operations — ARP requests, TCP SYN scans, UDP probes, ICMP traceroute, and Layer 2 attack frames — are handled by [Scapy](https://scapy.net/), giving PyNetKit precise, low-level control over the network stack without relying on external system tools like `nmap` or `traceroute`.

The toolkit is structured around three concerns: **discovery** (find hosts and open ports on a local subnet), **intelligence** (fingerprint OS families, trace network paths, log DNS activity), and **auditing** (ARP poisoning MiTM, ARP-based DoS blackholing, DHCP starvation).

<br>
<div align="center">

**GUI — Host Discovery and Attack Console**
> *Scanning a subnet, inspecting discovered hosts, and navigating the per-host attack tabs (Port Scanner, ARP Poisoning, DoS, Traceroute).*

![GUI Overview Demo](docs/demo_gui.gif)

</div>

---

## 💫 Features

**Network Discovery**
- ARP broadcast scanning across any local subnet — single IP or CIDR range.
- Resolves both IP and MAC address for every responding host.

**Port Scanning**
- **TCP SYN scan** — classifies ports as `open` (SYN-ACK), `closed` (RST-ACK), or `filtered` (no response).
- **UDP scan** — probes UDP ports and uses ICMP unreachable replies to determine state; unanswered probes are reported as `open|filtered`.
- **Service identification** — maps common port numbers (22, 80, 443, 3306, 3389, etc.) to well-known service names.
- **OS fingerprinting** — infers broad OS family (Linux/Unix, Windows, Cisco/Network Device) from the TTL value in responses.

**Traceroute**
- ICMP-based path tracing with configurable maximum hops and per-hop round-trip time measurement.
- Accepts hostnames in addition to IPs; resolves names via a direct Scapy DNS query to `8.8.8.8`.

**ARP Poisoning (Man-in-the-Middle)**
- Simultaneously poisons both the target and the gateway to intercept bidirectional traffic.
- Forwards all captured packets in real time so the target's connection remains live.
- **PCAP capture** — optionally writes intercepted traffic to a timestamped `.pcap` file organized under `hosts/<target_ip>/captures/`.
- **DNS spoofing** — intercepts DNS queries for a specified domain and returns a custom IP, enabling silent traffic redirection.
- Tracks and persists all domains queried by the target during the session to `hosts/<target_ip>/visited_domains.txt`.
- Restores both ARP tables cleanly on stop, whether exited normally or via `Ctrl+C`.

**Denial of Service**
- **Single-target blackhole** — poisons the target and gateway with two distinct dummy MACs, dropping all inbound and outbound traffic for the chosen host without forwarding anything. Sets a static ARP entry on the attacker's own machine to prevent self-poisoning.
- **DHCP starvation** — floods the network with DHCP Discover packets using randomized source MACs and transaction IDs, exhausting the DHCP address pool for all devices on the segment.

**Dual Interface**
- **CLI** — Rich-formatted panels, tables, and progress indicators. Full `argparse` subcommand structure (`scan`, `arp`, `dos single`, `dos network`, `trace`) with input validation and helpful error output.
- **GUI** — ttkbootstrap dark-mode window. Split-pane layout: host discovery table on top, tabbed detail view (Port Scanner, ARP Poisoning, DoS, Traceroute) on the bottom. All network operations run in background threads to keep the UI responsive.

---

## 🌌 Project Structure

```sh
└── pynetkit/
    ├── LICENSE
    ├── pyproject.toml
    ├── requirements.txt
    ├── pynetkit/
    │   ├── __init__.py
    │   ├── attacks.py
    │   ├── cli.py
    │   ├── gui.py
    │   ├── main.py
    │   ├── models.py
    │   ├── scanner.py
    │   └── utils.py
    └── tests/
        ├── test_models.py
        ├── test_scanner.py
        └── test_utils.py
```

### ✨ Project Index

<details open>
	<summary><b><code>pynetkit/</code></b></summary>
	<!-- __root__ Submodule -->
	<details>
		<summary><b>Root</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ project root</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='LICENSE'>LICENSE</a></b></td>
					<td style='padding: 8px;'>MIT license file governing the redistribution and use of the project.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pyproject.toml'>pyproject.toml</a></b></td>
					<td style='padding: 8px;'>Build configuration defining project metadata, pinned dependencies (Scapy, Rich, ttkbootstrap), and the <code>pynetkit</code> console entry point that maps to <code>pynetkit.main:main</code>.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='requirements.txt'>requirements.txt</a></b></td>
					<td style='padding: 8px;'>Flat list of pinned runtime and development dependencies for use with <code>pip install -r</code>.</td>
				</tr>
			</table>
		</blockquote>
	</details>
	<!-- pynetkit Submodule -->
	<details>
		<summary><b>pynetkit</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ pynetkit</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/main.py'>main.py</a></b></td>
					<td style='padding: 8px;'>Application entry point: validates root/admin privileges and dispatches to the GUI (<code>-g</code>) or CLI based on the supplied arguments.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/cli.py'>cli.py</a></b></td>
					<td style='padding: 8px;'>Rich-based CLI: defines all subcommands (<code>scan</code>, <code>arp</code>, <code>dos</code>, <code>trace</code>), validates arguments, and orchestrates calls into the scanner and attack modules with formatted terminal output.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/gui.py'>gui.py</a></b></td>
					<td style='padding: 8px;'>ttkbootstrap GUI: split-pane dark-mode window with a host discovery table on top and per-host detail tabs (Port Scanner, ARP Poisoning, DoS, Traceroute) on the bottom, using background threads for all blocking network operations.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/attacks.py'>attacks.py</a></b></td>
					<td style='padding: 8px;'>Implements the three attack classes — <code>ArpPoisoning</code> (bidirectional MiTM with optional PCAP capture and DNS spoofing), <code>DHCPStarvation</code>, and <code>SingleTargetDos</code> — each with threaded start/stop lifecycle management and clean table restoration.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/scanner.py'>scanner.py</a></b></td>
					<td style='padding: 8px;'>Provides <code>NetworkScanner</code> (ARP host discovery, TCP SYN and UDP port scanning with TTL-based OS fingerprinting) and <code>TraceScanner</code> (ICMP traceroute with Scapy-based DNS hostname resolution).</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/models.py'>models.py</a></b></td>
					<td style='padding: 8px;'>Defines the <code>Host</code> and <code>Port</code> data classes that carry discovered network state (IP, MAC, OS guess, port list) across the scanner, attack, and UI layers.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='pynetkit/utils.py'>utils.py</a></b></td>
					<td style='padding: 8px;'>Shared utilities: ARP-based MAC resolution with retries, cross-platform default gateway detection (PowerShell / <code>ip route</code> / <code>route</code>), IP/port string validation, TTL-to-OS mapping, and static ARP entry management for self-poisoning protection.</td>
				</tr>
			</table>
		</blockquote>
	</details>
	<!-- tests Submodule -->
	<details>
		<summary><b>tests</b></summary>
		<blockquote>
			<div class='directory-path' style='padding: 8px 0; color: #666;'>
				<code><b>⦿ tests</b></code>
			<table style='width: 100%; border-collapse: collapse;'>
			<thead>
				<tr style='background-color: #f8f9fa;'>
					<th style='width: 30%; text-align: left; padding: 8px;'>File Name</th>
					<th style='text-align: left; padding: 8px;'>Summary</th>
				</tr>
			</thead>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='tests/test_models.py'>test_models.py</a></b></td>
					<td style='padding: 8px;'>Unit tests verifying initialization and <code>add_port</code> behavior of the <code>Host</code> and <code>Port</code> model classes.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='tests/test_scanner.py'>test_scanner.py</a></b></td>
					<td style='padding: 8px;'>Unit tests for <code>NetworkScanner</code> host discovery and port scanning logic, using mocked Scapy <code>srp</code> responses to avoid live network traffic.</td>
				</tr>
				<tr style='border-bottom: 1px solid #eee;'>
					<td style='padding: 8px;'><b><a href='tests/test_utils.py'>test_utils.py</a></b></td>
					<td style='padding: 8px;'>Unit tests covering IP/port validation edge cases and TTL-to-OS family mapping across boundary values.</td>
				</tr>
			</table>
		</blockquote>
	</details>
</details>

---

## ⚡ Getting Started

### 💠 Prerequisites

- **Python** >= 3.8
- **pip**

> [!WARNING]
> **Windows: Npcap is required**
>
> Scapy requires Npcap for Layer 2 packet capture and injection on Windows. Without it, every feature in PyNetKit — scanning, attacks, and traceroute — will fail silently or error on startup.
>
> 1. Download the Npcap installer from **[npcap.com/#download](https://npcap.com/#download)**
> 2. During installation, **check "Install Npcap in WinPcap API-compatible Mode"**
> 3. Reboot if prompted, then proceed with the installation steps below.

### 🔷 Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/OhadBragin/pynetkit.git
    ```

2. **Navigate to the project directory:**

    ```sh
    cd pynetkit
    ```

3. **Install the package and its dependencies:**

	**Using [pip](https://pypi.org/project/pip/):**

	```sh
	pip install -e .
	```

### 🔹 Usage

All features require elevated privileges — run with `sudo` on Linux/macOS, or from an **Administrator** terminal on Windows.

**Launch the GUI:**

```sh
# Linux / macOS
sudo pynetkit -g

# Windows (Administrator terminal)
pynetkit -g
```

<div align="center">

**CLI — Subnet Scan with Port Detection**
> *ARP host discovery across a /24, followed by TCP SYN and UDP port scanning with service names and OS fingerprinting, rendered in Rich panels.*

![CLI Scan Demo](docs/demo_cli_scan.gif)

</div>

**Discover hosts on a subnet:**
```sh
sudo pynetkit scan 192.168.1.0/24 -i eth0
```

**Discover hosts and scan ports:**
```sh
sudo pynetkit scan 192.168.1.0/24 -i eth0 -p -r 1-1024
```

<div align="center">

**CLI — ARP Poisoning with DNS Spoofing**
> *Resolving target and gateway MACs, launching a bidirectional MiTM attack with DNS redirection active, and cleanly restoring ARP tables on stop.*

![CLI ARP Demo](docs/demo_cli_arp.gif)

</div>

**Run an ARP poisoning (MiTM) attack:**
```sh
sudo pynetkit arp 192.168.1.50 -i eth0
```

**ARP poisoning with DNS spoofing and PCAP capture:**
```sh
sudo pynetkit arp 192.168.1.50 -i eth0 --dns-domain example.com --dns-ip 10.0.0.1 -s
```

**Single-target DoS (ARP blackhole):**
```sh
sudo pynetkit dos single 192.168.1.50 -i eth0
```

**Network-wide DHCP starvation:**
```sh
sudo pynetkit dos network -i eth0
```

**Traceroute to a host:**
```sh
sudo pynetkit trace google.com
```

For the full argument reference:
```sh
pynetkit --help
pynetkit scan --help
pynetkit arp --help
pynetkit dos --help
```

### 🔸 Testing

PyNetKit uses the [pytest](https://docs.pytest.org/) test framework. Run the full test suite with:

**Using [pip](https://pypi.org/project/pip/):**
```sh
pytest
```

---

## 🤖 AI Transparency

AI-assisted tooling (large language models) was used during development to help generate boilerplate code, UI layout scaffolding, and portions of this documentation. All generated output was reviewed, modified where necessary, and assembled by the author. Architecture decisions, feature design, and core logic are the author's own work.

---

## ⭐ License

PyNetKit is licensed under the [MIT License](LICENSE). For more details, refer to the [LICENSE](LICENSE) file.

---

<div align="right">

[![][back-to-top]](#top)

</div>

[back-to-top]: https://img.shields.io/badge/-BACK_TO_TOP-151515?style=flat-square