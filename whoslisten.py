#!/usr/bin/env python3
"""
whoslisten - A Linux network service discovery tool
by Noobosaurus R3x
Version : 1.0
========================================
* Clean, focused interface with essential features only
* Enhanced security analysis with intelligent filtering
* Real-time monitoring with smart defaults
* Multiple export formats with auto-detection
"""

import argparse
import csv
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Set
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

# Constants
PROC_TCP_FILES = {
    "tcp": "/proc/net/tcp",
    "tcp6": "/proc/net/tcp6", 
    "udp": "/proc/net/udp",
    "udp6": "/proc/net/udp6",
}

LISTEN_STATE = "0A"
SOCKET_RE = re.compile(r"socket:\[(\d+)]")
GETCAP_BIN = shutil.which("getcap")
DEFAULT_MAX_PATH = 48

# Common service ports
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 
    80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
    995: "pop3s", 3306: "mysql", 5432: "postgresql", 6379: "redis",
    27017: "mongodb", 3389: "rdp", 1433: "mssql", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 5601: "kibana"
}

# Legitimate processes that use high ports
LEGITIMATE_HIGH_PORT_PROCESSES = {
    "kdeconnectd", "avahi-daemon", "containerd", "dockerd", "chrome", "firefox", 
    "brave", "discord", "steam", "spotify", "systemd", "NetworkManager",
    "systemd-resolve", "pulseaudio", "pipewire", "gnome-shell", "plasma",
    "xorg", "wayland", "gdm", "sddm", "lightdm", "code", "vscode", "electron",
    "mattermost-desk", "slack", "teams", "zoom", "skype", "signal-desktop",
    "telegram-desktop", "whatsapp", "thunderbird", "evolution", "caido"
}

SUSPICIOUS_PATTERNS = {
    "crypto_miners": ["xmrig", "cpuminer", "ethminer", "claymore", "t-rex", "phoenixminer"],
    "network_tools": ["ncat", "socat", "netcat", "nc"],
    "reverse_shells": ["bash", "sh", "cmd", "powershell"],
    "suspicious_names": ["backdoor", "shell", "reverse", "bind", "exploit"],
}


@dataclass
class ServiceEntry:
    protocol: str
    local_ip: str
    port: int
    pid: int
    exe: str
    sha256: Optional[str]
    capabilities: Optional[str]
    user: str
    cmdline: str
    parent_pid: int
    service_name: Optional[str]
    interface: str
    is_privileged: bool
    is_suspicious: bool
    created_time: float

    @property
    def comm(self) -> str:
        try:
            return Path(f"/proc/{self.pid}/comm").read_text().strip()[:24]
        except (FileNotFoundError, PermissionError):
            return "?"

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_time

    def to_table_row(self, max_path: int) -> Sequence[str]:
        caps = self.capabilities if self.capabilities else "—"
        exe_disp = _shorten(self.exe, max_path)
        service_name = self.service_name or "—"
        
        return [
            self.protocol,
            str(self.port),
            service_name,
            str(self.pid),
            self.comm,
            exe_disp,
            self.sha256[:8] if self.sha256 else "?",
            caps,
            self.user,
            self.local_ip,
        ]


def _shorten(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    basename = os.path.basename(s)
    if len(basename) + 4 >= max_len:
        return "…" + basename[-(max_len - 1):]
    return "…" + s[-(max_len - 1):]


def _parse_address(hex_addr: str) -> Tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:
        ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
    else:
        ip = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(ip_hex)[::-1])
    return ip, port


def _get_interface_for_ip(ip: str) -> str:
    try:
        if "." in ip:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 2:
                        dest_hex = fields[1]
                        if dest_hex == "00000000":
                            return fields[0]
            return "lo" if ip.startswith("127.") else "unknown"
        else:
            return "lo" if ip == "::1" else "unknown"
    except Exception:
        return "unknown"


def _iter_sockets() -> List[Tuple[str, str, int, str]]:
    sockets: List[Tuple[str, str, int, str]] = []
    for proto, path in PROC_TCP_FILES.items():
        try:
            with open(path, "r", encoding="utf-8") as fp:
                next(fp)
                for line in fp:
                    parts = line.split()
                    if not parts:
                        continue
                    if proto.startswith("tcp") and parts[3] != LISTEN_STATE:
                        continue
                    ip, port = _parse_address(parts[1])
                    inode = parts[9]
                    sockets.append((proto, ip, port, inode))
        except FileNotFoundError:
            continue
    return sockets


def _build_inode_pid_map() -> Dict[str, int]:
    inode_pid: Dict[str, int] = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            continue
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                m = SOCKET_RE.match(link)
                if m and m.group(1) not in inode_pid:
                    inode_pid[m.group(1)] = int(pid)
        except PermissionError:
            continue
    return inode_pid


def _sha256sum_lazy(path: str, compute: bool = True) -> Optional[str]:
    if not compute or path == "?":
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb", buffering=65536) as fp:
            for chunk in iter(lambda: fp.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _get_capabilities(path: str) -> Optional[str]:
    if not GETCAP_BIN or path == "?":
        return None
    try:
        res = subprocess.run(
            [GETCAP_BIN, "-n", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
        if " = " in res.stdout:
            return res.stdout.strip().split(" = ", 1)[1]
    except Exception:
        pass
    return None


def _get_process_info(pid: int) -> Tuple[str, str, int, float]:
    try:
        stat_info = os.stat(f"/proc/{pid}")
        user = pwd.getpwuid(stat_info.st_uid).pw_name
        
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_text()
            cmdline = " ".join(cmdline.split("\0")).strip()
            if not cmdline:
                cmdline = f"[{Path(f'/proc/{pid}/comm').read_text().strip()}]"
        except:
            cmdline = "?"
            
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_text()
            ppid = int(stat_line.split()[3])
        except:
            ppid = -1
            
        created_time = stat_info.st_ctime
        return user, cmdline, ppid, created_time
        
    except (FileNotFoundError, PermissionError, KeyError):
        return "?", "?", -1, time.time()


def _is_suspicious_process(exe: str, cmdline: str, port: int, comm: str = "") -> bool:
    if exe == "?" or cmdline == "?":
        return False
        
    exe_basename = os.path.basename(exe).lower()
    cmdline_lower = cmdline.lower()
    comm_lower = comm.lower()
    
    # Skip legitimate processes
    if comm_lower in LEGITIMATE_HIGH_PORT_PROCESSES:
        return False
    if any(legit in exe_basename for legit in LEGITIMATE_HIGH_PORT_PROCESSES):
        return False
    
    # More intelligent high port detection
    if port > 49152:
        if not any(safe_pattern in exe_basename for safe_pattern in 
                  ["systemd", "resolved", "daemon", "manager", "proxy"]):
            if not any(pattern in cmdline_lower for pattern in 
                      ["--port", "--listen", "--bind", "server", "daemon"]):
                return True
    
    # Check for crypto miners
    for pattern in SUSPICIOUS_PATTERNS["crypto_miners"]:
        if pattern in exe_basename or pattern in cmdline_lower:
            return True
            
    # Check for network tools
    for pattern in SUSPICIOUS_PATTERNS["network_tools"]:
        if pattern in exe_basename:
            return True
    
    # Check for suspicious names
    for pattern in SUSPICIOUS_PATTERNS["suspicious_names"]:
        if pattern in exe_basename or pattern in cmdline_lower:
            return True
            
    # Check for reverse shells
    if any(shell in exe_basename for shell in SUSPICIOUS_PATTERNS["reverse_shells"]):
        if any(keyword in cmdline_lower for keyword in ["-e", "-c", "exec", "spawn", "/dev/tcp"]):
            return True
    
    # Check for suspicious commands
    if any(pattern in cmdline_lower for pattern in 
           ["wget", "curl"] + ["http://", "https://"] + 
           ["base64", "echo", "|sh", "|bash"]):
        return True
            
    return False


def _is_privileged_process(user: str, capabilities: Optional[str]) -> bool:
    if user == "root":
        return True
    if capabilities and capabilities != "—":
        return True
    return False


def _explain_suspicious(exe: str, cmdline: str, port: int, comm: str = "") -> List[str]:
    reasons = []
    if exe == "?" or cmdline == "?":
        return reasons
        
    exe_basename = os.path.basename(exe).lower()
    cmdline_lower = cmdline.lower()
    comm_lower = comm.lower()
    
    # Skip legitimate processes
    if comm_lower in LEGITIMATE_HIGH_PORT_PROCESSES:
        return reasons
    if any(legit in exe_basename for legit in LEGITIMATE_HIGH_PORT_PROCESSES):
        return reasons
    
    # Check high port
    if port > 49152:
        if not any(safe_pattern in exe_basename for safe_pattern in 
                  ["systemd", "resolved", "daemon", "manager", "proxy"]):
            if not any(pattern in cmdline_lower for pattern in 
                      ["--port", "--listen", "--bind", "server", "daemon"]):
                reasons.append(f"High ephemeral port: {port}")
    
    # Check crypto miners
    for pattern in SUSPICIOUS_PATTERNS["crypto_miners"]:
        if pattern in exe_basename or pattern in cmdline_lower:
            reasons.append(f"Crypto miner pattern: {pattern}")
            
    # Check network tools
    for pattern in SUSPICIOUS_PATTERNS["network_tools"]:
        if pattern in exe_basename:
            reasons.append(f"Network tool: {pattern}")
    
    # Check suspicious names
    for pattern in SUSPICIOUS_PATTERNS["suspicious_names"]:
        if pattern in exe_basename or pattern in cmdline_lower:
            reasons.append(f"Suspicious name: {pattern}")
            
    # Check reverse shells
    if any(shell in exe_basename for shell in SUSPICIOUS_PATTERNS["reverse_shells"]):
        if any(keyword in cmdline_lower for keyword in ["-e", "-c", "exec", "spawn", "/dev/tcp"]):
            reasons.append("Potential reverse shell")
    
    # Check suspicious commands
    if any(pattern in cmdline_lower for pattern in 
           ["wget", "curl"] + ["http://", "https://"] + 
           ["base64", "echo", "|sh", "|bash"]):
        reasons.append("Suspicious command pattern")
            
    return reasons


def scan_services(compute_hashes: bool = True, progress_callback=None) -> List[ServiceEntry]:
    sockets = _iter_sockets()
    inode_pid = _build_inode_pid_map()
    services: List[ServiceEntry] = []
    
    total = len(sockets)
    for i, (proto, ip, port, inode) in enumerate(sockets):
        if progress_callback:
            progress_callback(i + 1, total)
            
        pid = inode_pid.get(inode, -1)
        exe_path = "?"
        sha256 = None
        caps: Optional[str] = None
        user, cmdline, parent_pid, created_time = "?", "?", -1, time.time()
        
        if pid != -1:
            exe_link = f"/proc/{pid}/exe"
            if os.path.exists(exe_link):
                try:
                    exe_path = os.path.realpath(exe_link)
                    sha256 = _sha256sum_lazy(exe_path, compute_hashes)
                    caps = _get_capabilities(exe_path)
                except:
                    pass
            user, cmdline, parent_pid, created_time = _get_process_info(pid)
        
        service_name = COMMON_PORTS.get(port)
        interface = _get_interface_for_ip(ip)
        
        # Get comm for better suspicious detection
        comm = ""
        if pid != -1:
            try:
                comm = Path(f"/proc/{pid}/comm").read_text().strip()
            except:
                pass
        
        is_suspicious = _is_suspicious_process(exe_path, cmdline, port, comm)
        is_privileged = _is_privileged_process(user, caps)
        
        services.append(
            ServiceEntry(
                protocol=proto,
                local_ip=ip,
                port=port,
                pid=pid,
                exe=exe_path,
                sha256=sha256,
                capabilities=caps,
                user=user,
                cmdline=cmdline,
                parent_pid=parent_pid,
                service_name=service_name,
                interface=interface,
                is_privileged=is_privileged,
                is_suspicious=is_suspicious,
                created_time=created_time,
            )
        )
    
    services.sort(key=lambda s: (s.protocol, s.port))
    return services


def monitor_services(interval: int = 5, show_diff: bool = True, show_periodic: bool = True, 
                    show_initial_table: bool = False, ignore_ephemeral: bool = False) -> None:
    console = Console() if HAVE_RICH else None
    previous_services: Set[Tuple[str, int, int]] = set()
    scan_count = 0
    
    # Processes that commonly create/destroy ephemeral ports (noise)
    ephemeral_processes = {"brave", "chrome", "firefox", "discord", "mattermost-desk", 
                          "slack", "teams", "zoom", "spotify", "steam"}
    
    print(f"📡 Starting continuous monitoring (interval: {interval}s)")
    if ignore_ephemeral:
        print("🔇 Ignoring ephemeral ports from browsers and chat apps")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            scan_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if console:
                with console.status(f"[bold green]Scanning... ({timestamp})[/]", spinner="dots"):
                    services = scan_services(compute_hashes=False)
            else:
                print(f"🔍 Scanning... ({timestamp})", end=" ", flush=True)
                services = scan_services(compute_hashes=False)
                print("✅")
            
            # Filter out ephemeral processes if requested
            if ignore_ephemeral:
                services = [s for s in services if s.comm.lower() not in ephemeral_processes]
            
            current_services = {(s.protocol, s.port, s.pid) for s in services}
            
            # Show initial state
            if scan_count == 1:
                if show_initial_table:
                    print("📊 Initial service state:")
                    _print_table(services, DEFAULT_MAX_PATH, console is not None, False)
                    print(f"\n🔍 Now monitoring for changes every {interval}s...\n")
                else:
                    if console:
                        console.print(f"[bold cyan]📊 Initial scan: {len(services)} services found[/]")
                    else:
                        print(f"📊 Initial scan: {len(services)} services found")
                        
                    # Show a summary of the initial services
                    tcp_count = sum(1 for s in services if s.protocol.startswith('tcp'))
                    udp_count = sum(1 for s in services if s.protocol.startswith('udp'))
                    suspicious_count = sum(1 for s in services if s.is_suspicious)
                    
                    summary = f"   TCP: {tcp_count}, UDP: {udp_count}"
                    if suspicious_count > 0:
                        summary += f", Suspicious: {suspicious_count}"
                    print(summary)
                    print(f"   Monitoring for changes every {interval}s...\n")
                
            elif show_periodic and scan_count % 10 == 0:  # Heartbeat every 10 scans
                if console:
                    console.print(f"[dim]💓 Heartbeat: {len(services)} services active ({timestamp})[/]")
                else:
                    print(f"💓 Heartbeat: {len(services)} services active ({timestamp})")
            
            # Check for changes
            if show_diff and previous_services:
                new_services = current_services - previous_services
                gone_services = previous_services - current_services
                
                if new_services or gone_services:
                    if console:
                        console.print(f"\n[bold yellow]🔄 Changes detected at {timestamp}[/]")
                    else:
                        print(f"\n🔄 Changes detected at {timestamp}")
                    
                    if new_services:
                        print("➕ New services:")
                        for proto, port, pid in new_services:
                            service = next(s for s in services if (s.protocol, s.port, s.pid) == (proto, port, pid))
                            user_info = f" ({service.user})" if service.user != "?" else ""
                            suspicious_flag = " ⚠️" if service.is_suspicious else ""
                            print(f"   {proto}:{port} (PID {pid}) - {service.comm}{user_info}{suspicious_flag}")
                    
                    if gone_services:
                        print("➖ Removed services:")
                        for proto, port, pid in gone_services:
                            print(f"   {proto}:{port} (PID {pid})")
                    
                    print()  # Extra line for readability
            
            previous_services = current_services
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n📡 Monitoring stopped after {scan_count} scans")


def _print_table(entries: List[ServiceEntry], max_path: int, color: bool, show_extended: bool = False) -> None:
    if color and HAVE_RICH:
        console = Console()
        table = Table(show_header=True, header_style="bold cyan", title="🛡️  Network Services Map")
        
        columns = ["Proto", "Port", "Service", "PID", "Comm", "Executable", "SHA256[:8]", "Caps", "User", "IP"]
        for col in columns:
            table.add_column(col)
        
        for e in entries:
            proto_style = "green" if e.protocol.startswith("tcp") else "magenta"
            user_style = "red bold" if e.user == "root" else "blue"
            
            row = [
                f"[{proto_style}]{e.protocol}[/]",
                str(e.port),
                e.service_name or "—",
                str(e.pid),
                e.comm,
                _shorten(e.exe, max_path),
                e.sha256[:8] if e.sha256 else "?",
                e.capabilities or "—",
                f"[{user_style}]{e.user}[/]",
                e.local_ip,
            ]
            
            # Highlight suspicious entries
            if e.is_suspicious:
                for i in range(len(row)):
                    if not row[i].startswith("["):
                        row[i] = f"[yellow]{row[i]}[/]"
            
            table.add_row(*row)
        
        console.print(table)
        
        # Summary panel
        total = len(entries)
        suspicious = sum(1 for e in entries if e.is_suspicious)
        privileged = sum(1 for e in entries if e.is_privileged)
        
        summary = f"Total: {total} | Suspicious: {suspicious} | Privileged: {privileged}"
        if suspicious > 0:
            summary += f"\n💡 Tip: Review suspicious entries manually - some may be false positives"
        console.print(Panel(summary, title="Summary", style="blue"))
        return

    # ASCII fallback
    headers = ["Proto", "Port", "Service", "PID", "Comm", "Executable", "SHA256[:8]", "Caps", "User", "IP"]
    col_widths = [len(h) for h in headers]
    rows = [e.to_table_row(max_path) for e in entries]
    
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    fmt = " ".join(f"{{:<{w}}}" for w in col_widths)
    print(fmt.format(*headers))
    print(" ".join("-" * w for w in col_widths))
    
    for row in rows:
        print(fmt.format(*row))


def _to_json(entries: List[ServiceEntry]) -> str:
    return json.dumps([asdict(e) for e in entries], indent=2, default=str)


def _to_csv(entries: List[ServiceEntry]) -> str:
    if not entries:
        return ""
    
    output = []
    fieldnames = list(asdict(entries[0]).keys())
    
    import io
    csvfile = io.StringIO()
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    
    for entry in entries:
        writer.writerow(asdict(entry))
    
    return csvfile.getvalue()


def _to_xml(entries: List[ServiceEntry]) -> str:
    root = ET.Element("services")
    
    for entry in entries:
        service_elem = ET.SubElement(root, "service")
        for key, value in asdict(entry).items():
            elem = ET.SubElement(service_elem, key)
            elem.text = str(value) if value is not None else ""
    
    return ET.tostring(root, encoding='unicode', xml_declaration=True)


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="servmap – network service discovery and monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  servmap                     # Scan and display services
  servmap --monitor           # Continuous monitoring  
  servmap --suspicious        # Show only suspicious services
  servmap --export data.json  # Export to file (auto-detects format)
  servmap --fast              # Quick scan without hashes
        """
    )
    
    # Core options (simplified)
    parser.add_argument("--monitor", action="store_true", help="Continuous monitoring mode")
    parser.add_argument("--suspicious", action="store_true", help="Show only suspicious services")
    parser.add_argument("--fast", action="store_true", help="Skip SHA256 computation for faster scanning")
    parser.add_argument("--export", metavar="FILE", help="Export to file (format auto-detected: .json, .csv, .xml)")
    parser.add_argument("--proto", choices=["tcp", "udp"], help="Filter by protocol (tcp or udp)")
    parser.add_argument("--quiet", action="store_true", help="Minimal output (monitoring mode)")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")

    args = parser.parse_args(argv)

    # Smart defaults for monitoring
    if args.monitor:
        interval = 5
        show_summary = not args.quiet
        ignore_noise = args.quiet  # Only filter noise in quiet mode
        
        if show_summary:
            # Show initial scan first
            services = scan_services(not args.fast)
            if args.proto:
                services = [e for e in services if e.protocol.startswith(args.proto)]
            if args.suspicious:
                services = [e for e in services if e.is_suspicious]
            
            print("📊 Current services:")
            _print_table(services, DEFAULT_MAX_PATH, not args.no_color, False)
            print()
        
        monitor_services(interval, True, not args.quiet, False, ignore_noise)
        return

    # Regular scan
    if HAVE_RICH and not args.no_color and not args.quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=Console()
        ) as progress:
            task = progress.add_task("Scanning services...", total=None)
            entries = scan_services(not args.fast)
    else:
        if not args.quiet:
            print("Scanning services...")
        entries = scan_services(not args.fast)

    # Apply filters
    if args.proto:
        entries = [e for e in entries if e.protocol.startswith(args.proto)]
    if args.suspicious:
        entries = [e for e in entries if e.is_suspicious]

    # Handle export
    if args.export:
        try:
            filepath = args.export
            ext = filepath.lower().split('.')[-1]
            
            if ext == "json":
                content = _to_json(entries)
            elif ext == "csv":
                content = _to_csv(entries)
            elif ext == "xml":
                content = _to_xml(entries)
            else:
                # Default to JSON if no extension
                content = _to_json(entries)
                if not filepath.endswith('.json'):
                    filepath += '.json'
            
            with open(filepath, "w") as f:
                f.write(content)
            print(f"✅ Exported {len(entries)} entries to {filepath}")
            
        except Exception as e:
            print(f"❌ Export failed: {e}")
            sys.exit(1)
    else:
        # Display results
        _print_table(entries, DEFAULT_MAX_PATH, not args.no_color, False)
        
        # Show explanations for suspicious entries
        if args.suspicious and entries:
            print("\n" + "="*60)
            print("🔍 WHY THESE ARE FLAGGED:")
            print("="*60)
            for entry in entries:
                reasons = _explain_suspicious(entry.exe, entry.cmdline, entry.port, entry.comm)
                if reasons:
                    print(f"\n🚨 {entry.protocol}:{entry.port} ({entry.comm})")
                    for reason in reasons:
                        print(f"   • {reason}")
                else:
                    print(f"\n❓ {entry.protocol}:{entry.port} ({entry.comm}) - Possible false positive")
            print("\n💡 Review each case manually to confirm threats.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
