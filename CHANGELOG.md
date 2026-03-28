\# Changelog



All notable changes to PyNetKit will be documented in this file.



The format follows \[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

PyNetKit uses \[Semantic Versioning](https://semver.org/spec/v2.0.0.html).



---



\## \[1.0.0] - 2026-03-29



Initial public release.



\### Added



\*\*Network Discovery\*\*

\- ARP broadcast scanning across any local subnet — single IP or CIDR range.

\- Resolves both IP and MAC address for every responding host.

\- MAC vendor lookup via bundled `vendorDB.txt` (short and long name).



\*\*Port Scanning\*\*

\- TCP SYN scan — classifies ports as `open` (SYN-ACK), `closed` (RST-ACK), or `filtered` (no response).

\- UDP scan — probes UDP ports and uses ICMP unreachable replies to determine state; unanswered probes reported as `open|filtered`.

\- Service identification — maps common port numbers to well-known service names.

\- OS fingerprinting — infers broad OS family (Unix, Windows, Cisco) from TTL values.



\*\*Traceroute\*\*

\- ICMP-based path tracing with configurable maximum hops and per-hop RTT measurement.

\- Hostname resolution via direct Scapy DNS query to `8.8.8.8`.



\*\*ARP Poisoning (Man-in-the-Middle)\*\*

\- Bidirectional ARP poisoning of target and gateway.

\- Real-time packet forwarding to keep the target's connection live.

\- PCAP capture — optionally writes intercepted traffic to a timestamped `.pcap` file.

\- DNS spoofing — intercepts DNS queries for a specified domain and returns a custom IP.

\- Visited domain logging to `hosts/<target\_ip>/visited\_domains.txt`.

\- Clean ARP table restoration on stop, whether exited normally or via `Ctrl+C`.

\- ARP shield — sets a static entry for the gateway on the attacker's machine to prevent self-poisoning (CLI and GUI).



\*\*Denial of Service\*\*

\- Single-target blackhole — poisons target and gateway with distinct dummy MACs, dropping all traffic without forwarding.

\- DHCP starvation — floods the network with DHCP Discover packets using randomized source MACs and transaction IDs.



\*\*Dual Interface\*\*

\- CLI — Rich-formatted panels, tables, and progress indicators. Full `argparse` subcommand structure (`scan`, `arp`, `dos single`, `dos network`, `trace`).

\- GUI — ttkbootstrap dark-mode window. Split-pane layout with tabbed detail view. All network operations run in background threads. Graceful window-close handler stops active attacks and restores ARP tables before exit.



\*\*Packaging\*\*

\- `pyproject.toml`-based packaging with a `pynetkit` entry point.

\- Cross-platform support for Windows (requires Npcap), Linux, and macOS.

\- Test suite covering attacks, models, scanner, and utilities.

