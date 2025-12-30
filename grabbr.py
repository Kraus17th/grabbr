#!/usr/bin/env python3

import argparse
import signal
import socket
import sys
import time
import threading
import queue
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from collections import defaultdict

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: rich library not available. Install with: pip install rich")
    sys.exit(1)


# ASCII Banner
BANNER = r"""
 ,----.                  ,--.   ,--.
'  .-./   ,--.--. ,--,--.|  |-. |  |-. ,--.--.
|  | .---.|  .--'' ,-.  || .-. '| .-. '|  .--'
'  '--'  ||  |   \ '-'  || `-' || `-' ||  |
 `------' `--'    `--`--' `---'  `---' `--'.py ver1.0.0 @Kraus17th
       # advanced banner grabbing
"""


class BannerGrabber:
    """Main class for banner grabbing functionality."""
    
    def __init__(self, args):
        self.args = args
        self.console = Console()
        self.targets: List[Tuple[str, int]] = []
        self.results: Dict[Tuple[str, int], Dict] = {}
        self.stats = defaultdict(int)
        self.lock = threading.Lock()
        self.rate_limiter = None
        self.excluded_ports = set()
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.interrupted = False
        
        if args.exclude_port:
            self.excluded_ports = {int(p.strip()) for p in args.exclude_port.split(',') if p.strip()}
        
        # Initialize rate limiter if specified
        if args.rate:
            self.rate_limiter = queue.Queue(maxsize=args.rate)
            for _ in range(args.rate):
                self.rate_limiter.put(time.time())
    
    def parse_targets(self):
        """Parse targets from various input sources."""
        if self.args.single_target:
            # Parse single target
            try:
                host, port = self.args.single_target.rsplit(':', 1)
                port = int(port)
                self.targets.append((host, port))
            except ValueError:
                self.console.print(f"[red]Error: Invalid target format '{self.args.single_target}'. Expected format: ip:port or hostname:port[/red]")
                sys.exit(1)
        
        elif self.args.file_with_targets:
            # Parse targets from file
            try:
                with open(self.args.file_with_targets, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                host, port = line.rsplit(':', 1)
                                port = int(port)
                                self.targets.append((host, port))
                            except ValueError:
                                if self.args.verbose:
                                    self.console.print(f"[yellow]Warning: Skipping invalid line: {line}[/yellow]")
            except FileNotFoundError:
                self.console.print(f"[red]Error: File '{self.args.file_with_targets}' not found[/red]")
                sys.exit(1)
        
        elif self.args.nmap_xml_import:
            # Parse targets from nmap XML
            try:
                tree = ET.parse(self.args.nmap_xml_import)
                root = tree.getroot()
                
                for host in root.findall('.//host'):
                    # Get IP address
                    address_elem = host.find('.//address[@addrtype="ipv4"]')
                    if address_elem is None:
                        address_elem = host.find('.//address[@addrtype="ipv6"]')
                    if address_elem is None:
                        continue
                    
                    ip = address_elem.get('addr')
                    
                    # Get open ports
                    for port_elem in host.findall('.//port[@state="open"]'):
                        port = int(port_elem.get('portid'))
                        self.targets.append((ip, port))
            except FileNotFoundError:
                self.console.print(f"[red]Error: File '{self.args.nmap_xml_import}' not found[/red]")
                sys.exit(1)
            except ET.ParseError as e:
                self.console.print(f"[red]Error: Invalid XML file: {e}[/red]")
                sys.exit(1)
        
        # Don't filter excluded ports here - we'll mark them in results
        # But check if we have any targets at all
        if not self.targets:
            self.console.print("[red]Error: No valid targets found[/red]")
            sys.exit(1)
    
    def load_payload(self) -> bytes:
        """Load payload from various sources."""
        payload = b"test\r\n"  # Default payload
        
        if self.args.payload_hex:
            # Load hex payload
            if Path(self.args.payload_hex).is_file():
                try:
                    with open(self.args.payload_hex, 'rb') as f:
                        payload = f.read()
                except Exception as e:
                    self.console.print(f"[red]Error reading hex payload file: {e}[/red]")
                    sys.exit(1)
            else:
                # Parse hex string
                try:
                    payload = bytes.fromhex(self.args.payload_hex.replace(' ', '').replace('\n', ''))
                except ValueError as e:
                    self.console.print(f"[red]Error: Invalid hex payload: {e}[/red]")
                    sys.exit(1)
        
        elif self.args.payload:
            # Load string payload
            if Path(self.args.payload).is_file():
                try:
                    with open(self.args.payload, 'r', encoding='utf-8', errors='ignore') as f:
                        payload = f.read().encode('utf-8')
                except Exception as e:
                    self.console.print(f"[red]Error reading payload file: {e}[/red]")
                    sys.exit(1)
            else:
                payload = self.args.payload.encode('utf-8')
        
        return payload
    
    def get_payload_display(self) -> str:
        """Get payload display string for configuration."""
        if self.args.payload_hex:
            if Path(self.args.payload_hex).is_file():
                # Return absolute path for hex file
                return str(Path(self.args.payload_hex).resolve())
            else:
                # Return hex string
                return self.args.payload_hex
        elif self.args.payload:
            if Path(self.args.payload).is_file():
                # Return absolute path for payload file
                return str(Path(self.args.payload).resolve())
            else:
                # Return payload string
                return self.args.payload
        else:
            # Default payload
            # Show escaped CRLF so it does not break layout in Configuration
            return "test\\r\\n"
    
    def parse_proxy(self):
        """Parse proxy configuration."""
        if not self.args.proxy:
            return None
        
        try:
            proxy_type, proxy_addr = self.args.proxy.split(':', 1)
            proxy_host, proxy_port = proxy_addr.rsplit(':', 1)
            proxy_port = int(proxy_port)
            return (proxy_type.lower(), proxy_host, proxy_port)
        except ValueError:
            self.console.print(f"[red]Error: Invalid proxy format '{self.args.proxy}'. Expected format: socks5:host:port or http:host:port[/red]")
            sys.exit(1)
    
    def setup_proxy(self, sock):
        """Setup proxy connection if specified."""
        proxy_config = self.parse_proxy()
        if not proxy_config:
            return sock
        
        proxy_type, proxy_host, proxy_port = proxy_config
        
        if proxy_type == 'socks5':
            if not SOCKS_AVAILABLE:
                self.console.print("[red]Error: pysocks library required for SOCKS proxy support. Install with: pip install pysocks[/red]")
                sys.exit(1)
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        elif proxy_type == 'socks4':
            if not SOCKS_AVAILABLE:
                self.console.print("[red]Error: pysocks library required for SOCKS proxy support. Install with: pip install pysocks[/red]")
                sys.exit(1)
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS4, proxy_host, proxy_port)
        elif proxy_type in ['http', 'https']:
            # HTTP proxy is handled separately in grab_banner
            return None
        else:
            self.console.print(f"[red]Error: Unsupported proxy type: {proxy_type}[/red]")
            sys.exit(1)
        
        return sock
    
    def connect_with_http_proxy(self, host, port, proxy_host, proxy_port, timeout=5):
        """Connect through HTTP proxy using CONNECT method."""
        try:
            # Connect to proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((proxy_host, proxy_port))
            
            # Send CONNECT request
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            sock.sendall(connect_req.encode())
            
            # Read response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            if '200' in response:
                return sock
            else:
                sock.close()
                return None
        except Exception as e:
            if self.args.verbose:
                self.console.print(f"[yellow]HTTP proxy connection error: {e}[/yellow]")
            return None
    
    def grab_banner(self, host: str, port: int, payload: bytes) -> Tuple[str, bool]:
        """Grab banner from a single target."""
        result = ""
        success = False
        
        if self.args.verbose:
            self.console.print(f"[dim]→ Connecting to {host}:{port}[/dim]")
        
        # Rate limiting
        if self.rate_limiter:
            try:
                last_time = self.rate_limiter.get(timeout=1)
                elapsed = time.time() - last_time
                if elapsed < 1.0:
                    if self.args.verbose:
                        self.console.print(f"[dim]  Rate limiting: waiting {1.0 - elapsed:.2f}s[/dim]")
                    time.sleep(1.0 - elapsed)
                self.rate_limiter.put(time.time())
            except queue.Empty:
                pass
        
        # Retry logic
        proxy_config = self.parse_proxy()
        is_http_proxy = proxy_config and proxy_config[0] in ['http', 'https']
        
        for attempt in range(self.args.retry):
            if self.interrupted:
                break
                
            if self.args.verbose and self.args.retry > 1:
                self.console.print(f"[dim]  Attempt {attempt + 1}/{self.args.retry}[/dim]")
            
            try:
                # Setup socket
                if is_http_proxy:
                    # HTTP proxy
                    _, proxy_host, proxy_port = proxy_config
                    if self.args.verbose:
                        self.console.print(f"[dim]  Connecting through HTTP proxy {proxy_host}:{proxy_port}[/dim]")
                    sock = self.connect_with_http_proxy(host, port, proxy_host, proxy_port, timeout=5)
                    if sock is None:
                        if self.args.verbose:
                            self.console.print(f"[yellow]  ✗ HTTP proxy connection failed[/yellow]")
                        continue
                else:
                    # Direct connection or SOCKS proxy
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
                    if proxy_config:
                        proxy_type, proxy_host, proxy_port = proxy_config
                        if self.args.verbose:
                            self.console.print(f"[dim]  Connecting through {proxy_type.upper()} proxy {proxy_host}:{proxy_port}[/dim]")
                        sock = self.setup_proxy(sock)
                        if sock is None:
                            # HTTP proxy case (shouldn't happen here, but safety check)
                            continue
                    elif self.args.verbose:
                        self.console.print(f"[dim]  Direct connection[/dim]")
                    
                    sock.connect((host, port))
                    if self.args.verbose:
                        self.console.print(f"[green]  ✓ Connected to {host}:{port}[/green]")
                
                # Send payload
                if self.args.verbose:
                    payload_preview = payload[:50].decode('utf-8', errors='ignore') if len(payload) <= 50 else payload[:50].decode('utf-8', errors='ignore') + '...'
                    self.console.print(f"[dim]  Sending payload ({len(payload)} bytes): {repr(payload_preview)}[/dim]")
                sock.sendall(payload)
                
                # Receive response
                sock.settimeout(2)
                if self.args.verbose:
                    self.console.print(f"[dim]  Waiting for response...[/dim]")
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        result += chunk.decode('utf-8', errors='ignore')
                        if self.args.verbose:
                            self.console.print(f"[dim]  Received {len(chunk)} bytes (total: {len(result)} bytes)[/dim]")
                        if len(result) > 8192:  # Limit response size
                            if self.args.verbose:
                                self.console.print(f"[yellow]  Response size limit reached (8192 bytes)[/yellow]")
                            break
                except socket.timeout:
                    if self.args.verbose:
                        self.console.print(f"[dim]  Response timeout (normal)[/dim]")
                    pass  # Normal timeout after receiving initial data
                
                sock.close()
                success = True
                if self.args.verbose:
                    response_preview = result[:100] if len(result) <= 100 else result[:100] + '...'
                    self.console.print(f"[green]  ✓ Success: received {len(result)} bytes[/green]")
                    if result:
                        self.console.print(f"[dim]  Response preview: {repr(response_preview)}[/dim]")
                break
                
            except socket.timeout:
                with self.lock:
                    self.stats['timeout'] += 1
                if self.args.verbose:
                    self.console.print(f"[red]  ✗ Connection timeout[/red]")
                if attempt < self.args.retry - 1:
                    if self.args.verbose:
                        self.console.print(f"[dim]  Retrying in 0.5s...[/dim]")
                    time.sleep(0.5)
                else:
                    result = "ERROR:host_timeout"
                break
            except ConnectionRefusedError:
                with self.lock:
                    self.stats['closed'] += 1
                if self.args.verbose:
                    self.console.print(f"[red]  ✗ Connection refused[/red]")
                if attempt < self.args.retry - 1:
                    if self.args.verbose:
                        self.console.print(f"[dim]  Retrying in 0.5s...[/dim]")
                    time.sleep(0.5)
                else:
                    result = "ERROR:connection_refused"
                break
            except Exception as e:
                with self.lock:
                    self.stats['error'] += 1
                if self.args.verbose:
                    self.console.print(f"[red]  ✗ Error: {str(e)[:100]}[/red]")
                if attempt < self.args.retry - 1:
                    if self.args.verbose:
                        self.console.print(f"[dim]  Retrying in 0.5s...[/dim]")
                    time.sleep(0.5)
                else:
                    result = f"ERROR:{str(e)[:50]}"
                break
        
        if not result and not success:
            result = "WARNING:empty_response"
        elif not result:
            result = "WARNING:empty_response"
        
        # Update stats
        with self.lock:
            if success and result and not result.startswith("ERROR") and not result.startswith("WARNING"):
                self.stats['success'] += 1
            elif 'empty_response' in result:
                self.stats['empty'] += 1
        
        return result, success
    
    def worker(self, targets_queue, payload, progress, task_id):
        """Worker thread for processing targets."""
        while not self.interrupted:
            try:
                host, port = targets_queue.get(timeout=1)
            except queue.Empty:
                break
            
            if self.interrupted:
                break
            
            # Check if port is excluded
            if port in self.excluded_ports:
                if self.args.verbose:
                    self.console.print(f"[dim]⊘ {host}:{port} - Excluded from scope[/dim]")
                with self.lock:
                    self.results[(host, port)] = {
                        'response': 'LOG:excluded_from_scope',
                        'status': '[E]'
                    }
                    self.stats['excluded'] += 1
                progress.update(task_id, advance=1)
                targets_queue.task_done()
                continue
            
            # Delay between requests
            if self.args.delay > 0:
                if self.args.verbose:
                    self.console.print(f"[dim]  Delay: {self.args.delay}s[/dim]")
                time.sleep(self.args.delay)
            
            # Grab banner
            if self.args.verbose:
                self.console.print(f"[cyan]Processing {host}:{port}[/cyan]")
            response, success = self.grab_banner(host, port, payload)
            
            with self.lock:
                status = '[+]' if success and response and not response.startswith(('ERROR', 'WARNING')) else \
                        '[!]' if 'empty_response' in response else '[-]'
                self.results[(host, port)] = {
                    'response': response,
                    'status': status
                }
                if self.args.verbose:
                    self.console.print(f"[dim]  Status: {status} for {host}:{port}[/dim]")
            
            progress.update(task_id, advance=1)
            targets_queue.task_done()
    
    def run(self):
        """Main execution method."""
        # Display banner
        self.console.print(BANNER, style="cyan")
        
        # Parse targets
        if self.args.verbose:
            self.console.print("[cyan]Parsing targets...[/cyan]")
        self.parse_targets()
        
        # Load payload
        payload = self.load_payload()
        
        # Get payload display info
        payload_display = self.get_payload_display()

        # Track start time
        self.start_time = datetime.now()
        
        # Display configuration
        self.console.print("\n[bold cyan]Configuration:[/bold cyan]")
        config_table = Table(show_header=False, box=None, padding=(0, 2))
        config_table.add_row("Targets:", str(len(self.targets)))
        config_table.add_row("Payload:", payload_display)
        config_table.add_row("Threads:", str(self.args.threads))
        config_table.add_row("Retry:", str(self.args.retry))
        config_table.add_row("Delay:", f"{self.args.delay}s")
        if self.args.rate:
            config_table.add_row("Rate limit:", f"{self.args.rate} req/s")
        if self.args.proxy:
            config_table.add_row("Proxy:", self.args.proxy)
        if self.excluded_ports:
            config_table.add_row("Excluded ports:", ', '.join(map(str, sorted(self.excluded_ports))))
        config_table.add_row("Output file:", self.args.output)
        self.console.print(config_table)
        self.console.print()
        
        # Create targets queue
        targets_queue = queue.Queue()
        for target in self.targets:
            targets_queue.put(target)
        
        # Setup signal handler for graceful shutdown
        def signal_handler(signum, frame):
            self.console.print("\n[yellow]\nInterrupted by user (Ctrl+C)[/yellow]")
            self.interrupted = True
            self.end_time = datetime.now()
            self.console.print("[yellow]Saving partial results...[/yellow]")
            self.write_results()
            self.console.print(f"[green]Partial results saved to: {self.args.output}[/green]")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Create progress bar
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                task_id = progress.add_task("[cyan]Grabbing banners...", total=len(self.targets))
                
                # Start worker threads
                threads = []
                for _ in range(self.args.threads):
                    t = threading.Thread(target=self.worker, args=(targets_queue, payload, progress, task_id))
                    t.daemon = True
                    t.start()
                    threads.append(t)
                
                # Wait for all threads to complete
                for t in threads:
                    t.join()
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)
        
        # Track end time
        self.end_time = datetime.now()

        # Write results to file
        self.write_results()
        
        # Display summary
        self.console.print("\n[bold green]Summary:[/bold green]")
        summary_table = Table(show_header=True, header_style="bold cyan")
        summary_table.add_column("Status", style="cyan")
        summary_table.add_column("Count", justify="right")
        summary_table.add_row("Success", str(self.stats['success']), style="green")
        summary_table.add_row("Empty Response", str(self.stats.get('empty', 0)), style="yellow")
        summary_table.add_row("Timeout", str(self.stats['timeout']), style="red")
        summary_table.add_row("Connection Closed", str(self.stats['closed']), style="red")
        summary_table.add_row("Errors", str(self.stats['error']), style="red")
        if self.stats.get('excluded', 0) > 0:
            summary_table.add_row("Excluded", str(self.stats['excluded']), style="dim")
        self.console.print(summary_table)
        self.console.print(f"\n[green]Results saved to: {self.args.output}[/green]")
    
    def write_results(self):
        """Write results to output file."""
        start_time_str = (self.start_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        end_time_str = (self.end_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        captured_count = len(self.results)
        
        # Determine target description
        if self.args.single_target:
            target_desc = self.args.single_target
        elif self.args.file_with_targets:
            target_desc = self.args.file_with_targets
        elif self.args.nmap_xml_import:
            target_desc = self.args.nmap_xml_import
        else:
            target_desc = "Unknown"
        
        with open(self.args.output, 'w', encoding='utf-8') as f:
            f.write(f"# Captured banners for: {target_desc}\n")
            f.write(f"# Captured {captured_count} banners")
            if self.interrupted:
                f.write(" (partial results - interrupted)")
            f.write("\n")
            f.write(f"# Started at {start_time_str}\n")
            f.write(f"# Finished at {end_time_str}\n\n")
            
            for (host, port), data in sorted(self.results.items()):
                status = data['status']
                response = data['response']
                
                f.write(f"===== {host}:{port} {status} =====\n")
                if response == 'EXCLUDED_FROM_SCOPE':
                    f.write("EXCLUDED_FROM_SCOPE\n")
                else:
                    f.write(response)
                    if not response.endswith('\n'):
                        f.write('\n')
                f.write("\n")


def print_help():
    """Print custom help message."""
    # Banner
    print(BANNER)
    
    # Usage line
    print("Usage: grabbr [-h] (-t HOST:PORT | -f FILE | -n FILE) [-p PAYLOAD | --payload-hex HEX] "
          "[-x TYPE:HOST:PORT] [-T N] [-r N] [-d SEC] [-R N] [-o FILE] [-e PORTS] [-v]")
    print()
        
    # Target Input
    print("Target Input (required, choose one):")
    print("  -t, --single-target [host:port]     single target: ip:port or hostname:port")
    print("  -f, --file-with-targets [FILE]      file with targets (one per line: ip:port)")
    print("  -n, --nmap-xml-import [FILE]        import from nmap XML (only open ports)")
    print()
    
    # Payload Options
    print("Payload Options (optional):")
    print('  -p, --payload [PAYLOAD]             payload string or file path (default: "test\r\n")')
    print("  --payload-hex [HEX]                 binary payload in hex or hex file path")
    print()
    
    # Network Options
    print("Network Options (optional):")
    print("  -x, --proxy [TYPE:HOST:PORT]        proxy: socks5:127.0.0.1:1080 or http:127.0.0.1:8080")
    print()
    
    # Performance Options
    print("Performance Options:")
    print("  -T, --threads [NUM]                 number of threads (default: 1)")
    print("  -r, --rate [NUM]                    limit requests per second (default: none)")
    print("  -d, --delay [SEC]                   delay between requests in seconds (default: 0.5)")
    print("  -R, --retry [NUM]                   retry attempts per target (default: 1)")
    print()
    
    # Output and Filtering
    print("Output and Filtering:")
    print("  -o, --output [FILE]                 output file (default: banners.txt)")
    print("  -e, --exclude-port [PORTS]          exclude ports: e.g. 443,80,8080")
    print()
    
    # Other Options
    print("Other options:")
    print("  -h, --help                          show this help message and exit")
    print("  -v, --verbose                       enable verbose output with debug information")
    print()

    # Examples
    print("Examples:")
    print()
    print("# Basic banner grabbing from single target")
    print("  grabbr -t 192.168.1.1:80")
    print()
    print("# Multi-threaded scanning with rate limit")
    print("  grabbr -f targets.txt -T 20 -r 50 -o results.txt")
    print()
    print("# Using Nmap XML with custom payload")
    print("  grabbr -n scan.xml -p \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\" -T 10")
    print()
    print("# Through SOCKS proxy with retry")
    print("  grabbr -f targets.txt -x socks5:127.0.0.1:1080 -T 5 -R 3")
    print()
    print("# Binary payload with verbose output")
    print("  grabbr -t 192.168.1.1:443 --payload-hex \"deadbeef\" -v")
    print()
    print("# Excluding common ports from scan")
    print("  grabbr -n scan.xml -e 443,80,8080,8443 -T 15")
    print()
    print("# Custom payload from file with delay")
    print("  grabbr -t 192.168.1.1:22 -p payload.txt -d 1.0 -v")
    print()
    print("# Rate-limited scanning through HTTP proxy")
    print("  grabbr -f targets.txt -x http:127.0.0.1:8080 -r 10 -d 0.1 -T 5")


def parse_arguments():
    """Parse command line arguments."""
    # Check for help flag first
    if '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)
    
    parser = argparse.ArgumentParser(
        prog='grabbr',
        add_help=False
    )
    
    # Options
    parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose output with debug information')
    
    # Target input (mutually exclusive) - required
    target_group = parser.add_argument_group('Target Input (required, choose one)')
    target_mutex = target_group.add_mutually_exclusive_group(required=True)
    target_mutex.add_argument('-t', '--single-target', metavar='host:port', help='single target: ip:port or hostname:port')
    target_mutex.add_argument('-f', '--file-with-targets', metavar='FILE', help='file with targets (one per line: ip:port)')
    target_mutex.add_argument('-n', '--nmap-xml-import', metavar='FILE', help='import from nmap XML (only open ports)')
    
    # Payload options (mutually exclusive)
    payload_group = parser.add_argument_group('Payload Options (optional)')
    payload_mutex = payload_group.add_mutually_exclusive_group()
    payload_mutex.add_argument('-p', '--payload', metavar='PAYLOAD', help='payload string or file path (default: "test\r\n")')
    payload_mutex.add_argument('--payload-hex', metavar='HEX', help='binary payload in hex or hex file path')
    
    # Network options
    network_group = parser.add_argument_group('Network Options (optional)')
    network_group.add_argument('-x', '--proxy', metavar='TYPE:HOST:PORT', help='proxy: socks5:127.0.0.1:1080 or http:127.0.0.1:8080')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('-T', '--threads', type=int, default=1, metavar='NUM', help='number of threads (default: 1)')
    perf_group.add_argument('-r', '--rate', type=int, metavar='NUM', help='limit requests per second (default: none)')
    perf_group.add_argument('-d', '--delay', type=float, default=0.5, metavar='SEC', help='delay between requests in seconds (default: 0.5)')
    perf_group.add_argument('-R', '--retry', type=int, default=1, metavar='NUM', help='retry attempts per target (default: 1)')
    
    # Output and filtering
    output_group = parser.add_argument_group('Output and Filtering')
    output_group.add_argument('-o', '--output', metavar='FILE', default='banners.txt', help='output file (default: banners.txt)')
    output_group.add_argument('-e', '--exclude-port', metavar='PORTS', help='exclude ports: e.g. 443,80,8080')
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    if not RICH_AVAILABLE:
        print("Error: rich library is required. Install with: pip install rich")
        sys.exit(1)
    
    try:
        grabber = BannerGrabber(args)
        grabber.run()
    except KeyboardInterrupt:
        # This should be handled by signal handler, but just in case
        if 'grabber' in locals():
            try:
                grabber.interrupted = True
                grabber.end_time = datetime.now()
                grabber.write_results()
            except:
                pass
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        console = Console()
        console.print(f"[red]Fatal error: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()

