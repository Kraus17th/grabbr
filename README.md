![](assets/deteact_logo_white.png)

# Grabbr — advanced banner grabbing

**grabbr.py** — a utility for automated banner grabbing from TCP services.  
Allows you to quickly and efficiently collect banners from multiple hosts and ports with proxy support, rate limiting, retries, and a live TUI.

```bash
└─$ python3 grabbr.py -h
 ,----.                  ,--.   ,--.
'  .-./   ,--.--. ,--,--.|  |-. |  |-. ,--.--.
|  | .---.|  .--'' ,-.  || .-. '| .-. '|  .--'
'  '--'  ||  |   \ '-'  || `-' || `-' ||  |
 `------' `--'    `--`--' `---'  `---' `--'.py ver1.0.0 @Kraus17th
       # advanced banner grabbing

Usage: grabbr [-h] (-t HOST:PORT | -f FILE | -n FILE) [-p PAYLOAD | --payload-hex HEX] \
       [-x TYPE:HOST:PORT] [-T N] [-r N] [-d SEC] [-R N] [-o FILE] [-e PORTS] [-v]

Target Input (required, choose one):
  -t, --single-target [host:port]     single target: ip:port or hostname:port
  -f, --file-with-targets [FILE]      file with targets (one per line: ip:port)
  -n, --nmap-xml-import [FILE]        import from nmap XML (only open ports)

Payload Options (optional):
  -p, --payload [PAYLOAD]             payload string or file path (default: "test\r\n")
  --payload-hex [HEX]                 binary payload in hex or hex file path

Network Options (optional):
  -x, --proxy [TYPE:HOST:PORT]        proxy: socks5:127.0.0.1:1080 or http:127.0.0.1:8080

Performance Options:
  -T, --threads [NUM]                 number of threads (default: 1)
  -r, --rate [NUM]                    limit requests per second (default: none)
  -d, --delay [SEC]                   delay between requests in seconds (default: 0.5)
  -R, --retry [NUM]                   retry attempts per target (default: 1)

Output and Filtering:
  -o, --output [FILE]                 output file (default: banners.txt)
  -e, --exclude-port [PORTS]          exclude ports: e.g. 443,80,8080

Other options:
  -h, --help                          show this help message and exit
  -v, --verbose                       enable verbose output with debug information
```

## Features

- **Multiple target sources**: Single target (`-t`), file with targets (`-f`), or Nmap XML import (`-n`)
- **Proxy support**: SOCKS4, SOCKS5, and HTTP proxies (`-x`)
- **Flexible payloads**: Text payloads or files (`-p`), binary/hex payloads or files (`--payload-hex`)
- **Multithreading**: Parallel banner grabbing with configurable threads (`-T`)
- **Rate limiting & delays**: Control request rate (`-r`) and delay between requests (`-d`)
- **Retries**: Automatic retry per target on errors (`-R`)
- **Port exclusion**: Exclude ports from scope (`-e`)
- **Live TUI**: Progress bar and stats (success/timeout/closed/errors/excluded) via `rich`
- **Verbose mode**: Detailed debug info about connections, proxies, payloads, and responses (`-v`)
- **Partial results on Ctrl+C**: Saves what has already been collected when interrupted
- **Structured output**: Clear per-target sections with status markers

## Installation

### Option 1: Install via pipx (recommended)

`pipx` lets you install and run Python CLI tools in isolated environments:

```bash
# Install pipx if not already installed
# On macOS/Linux:
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# On Windows:
python -m pip install --user pipx
python -m pipx ensurepath

# Install Grabbr via pipx
pipx install git+https://github.com/Kraus17th/grabbr.git

# Or if the repository is already cloned locally:
pipx install /path/to/grabbr
```

After installation, the `grabbr` command will be available globally.

### Option 2: Install via git clone

```bash
# Clone the repository
git clone https://github.com/Kraus17th/grabbr.git
cd grabbr

# (Optional but recommended) create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the utility
python grabbr.py -t 192.168.1.1:80
```

## Usage

### Basic Usage

```bash
# Grab banner from a single target
grabbr -t 192.168.1.1:80
# Grab banners from a file containing targets
grabbr -f targets.txt -o results.txt
# Import targets from Nmap XML file
grabbr -n scan.xml -T 10
```

### Advanced Usage

```bash
# With custom payload
grabbr -t 192.168.1.1:80 -p "GET / HTTP/1.1\r\n\r\n"
# With binary (hex) payload
grabbr -t 192.168.1.1:443 --payload-hex "deadbeef"
# With proxy
grabbr -f targets.txt -x socks5:127.0.0.1:1080
# With rate limiting and threading
grabbr -f targets.txt -T 20 -r 10 -d 0.1
# Exclude specific ports
grabbr -n scan.xml -e 443,80,8080
# Verbose mode with retry
grabbr -t 192.168.1.1:22 -R 3 -v
```

## Command-Line Options

### Target Input (Required, mutually exclusive)

- `-t, --single-target HOST:PORT` - Single target in format `ip:port` or `hostname:port`
- `-f, --file-with-targets FILE` - File containing list of targets (one per line, format: `ip:port`)
- `-n, --nmap-xml-import FILE` - Import targets from Nmap XML file (only open ports)

### Payload Options (Mutually exclusive)

- `-p, --payload PAYLOAD` - Payload string or path to file with payload (default: `"test\r\n"`)
- `--payload-hex HEX` - Binary payload in hex format or path to file with hex payload

### Proxy

- `-x, --proxy TYPE:HOST:PORT` - Proxy in format: `socks5:127.0.0.1:1080` or `http:127.0.0.1:8080`

### Output

- `-o, --output FILE` - Output file for results (default: `banners.txt`)

### Rate Limiting and Timing

- `-r, --rate N` - Limit requests per second
- `-R, --retry N` - Number of retry attempts per target (default: 1)
- `-d, --delay SEC` - Delay between requests in seconds (default: 0.5)

### Threading

- `-T, --threads N` - Number of threads (default: 1)

### Other Options

- `-e, --exclude-port PORTS` - Comma-separated list of ports to exclude (e.g., `443,80,8080`)
- `-v, --verbose` - Enable verbose output with debug information
- `-h, --help` - Show help message and exit

## Output Format

The utility generates a structured output file with the following format:

```bash
# Captured banners for: targets.txt
# Started at 2024-01-15 10:30:00
# Finished at 2024-01-15 10:35:00

===== 172.26.5.255:22 [+] =====
SSH-2.0-OpenSSH_8.0
Invalid SSH identification string.

===== 172.26.3.255:80 [+] =====
HTTP/1.1 400 Bad request
Content-length: 90
Cache-Control: no-cache
Connection: close
Content-Type: text/html

<html><body><h1>400 Bad request</h1>
Your browser sent an invalid request.
</body></html>

===== 172.26.4.66:10050 [!] =====
WARNING:empty_response

===== 172.26.9.75:25500 [-] =====
ERROR:host_timeout
```

### Status Indicators

- `[+]` - Successfully grabbed banner
- `[!]` - Empty response received
- `[-]` - Error occurred (timeout, connection refused, etc.)
- `[E]` - Port was excluded from scanning

## Target File Format

When using `-f/--file-with-targets`, the file should contain one target per line in the format `ip:port` or `hostname:port`:


```plain
192.168.1.1:80
192.168.1.2:443
example.com:22
10.0.0.1:8080
```

Lines starting with `#` are treated as comments and ignored.

## Nmap XML Import

When using `-n/--nmap-xml-import`, the utility parses Nmap XML output and extracts all hosts with open ports. Only ports with state "open" are included in the scan.

```bash
# Generate Nmap XML with
nmap -oX scan.xml -p- 192.168.1.0/24

# Then import
grabbr -n scan.xml -T 10
```

## Proxy Support

Grabbr supports multiple proxy types:

- **SOCKS5**: `-x socks5:127.0.0.1:1080`
- **SOCKS4**: `-x socks4:127.0.0.1:1080`
- **HTTP**: `-x http:127.0.0.1:8080`

Note: HTTP proxy support uses the CONNECT method and may have limitations compared to SOCKS proxies.

## Payload Options

### Text Payload

Use `-p/--payload` for text payloads:

```bash
# String payload
grabbr -t 192.168.1.1:80 -p "GET / HTTP/1.1\r\n\r\n"

# File payload
grabbr -t 192.168.1.1:80 -p payload.txt
```

### Binary Payload

Use `--payload-hex` for binary payloads:

```bash
# Hex string
grabbr -t 192.168.1.1:443 --payload-hex "deadbeef"

# Hex file
grabbr -t 192.168.1.1:443 --payload-hex payload.hex
```

If no payload is specified, the default payload `"test\r\n"` is used.

## Performance Tuning

- **Threads (`-T`)**: Increase for faster scanning (be careful not to overwhelm targets)
- **Rate Limit (`-r`)**: Use to control request rate and avoid detection
- **Delay (`-d`)**: Add delay between requests to be more stealthy
- **Retry (`-R`)**: Increase for unreliable networks

Example optimized command:

```bash
grabbr -f targets.txt -T 50 -r 100 -d 0.1 -R 2
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. **Proxy connection fails**: Verify proxy settings and ensure the proxy server is running

3. **No results**: Check if targets are reachable and ports are open

4. **Timeout errors**: Increase retry count with `-R` or check network connectivity

### Verbose Mode

Use `-v/--verbose` for detailed debug information:

```bash
grabbr -t 192.168.1.1:80 -v
```

## Requirements

- `Python 3.7`
- `pysocks >= 1.7.1`
- `rich >= 13.0.0`

## License

This project is distributed under the MIT license. See the `LICENSE` file for details.

## Disclaimer

This utility is intended for legal use only on servers to which you have explicit permission to access. Use on servers without permission may be illegal. The authors are not responsible for misuse of this tool. This utility is created for security and auditing. Always ensure you have the right to access target servers before use.

![](assets/deteact_logo_black.png)

