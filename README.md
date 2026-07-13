# SC-PT (Scanr-Pintoto)

**SC-PT** is a fast, multithreaded port scanner and version detection tool written in C++. It supports both IP and hostname targets with comprehensive scanning options including full port scanning, range scanning, common port scanning, and service version detection.

## Features

- 🔍 **Fast Port Scanning** - Multithreaded scanning with configurable thread count
- 🌐 **IP & Hostname Support** - Scan both IPv4 addresses and domain names
- 📡 **Version Detection** - Identifies service versions for common ports (SSH, HTTP, MySQL, PostgreSQL, Redis, etc.)
- 🎯 **Flexible Port Selection** - Single port, multiple ports, port ranges, or common ports
- ⏱️ **Configurable Timeout** - Adjust timeout per connection
- 📊 **Progress Tracking** - Visual progress indicator for large scans
- 🎨 **Colorized Output** - Easy-to-read colored terminal output
- 🛡️ **Graceful Interruption** - Handles Ctrl+C gracefully

## Installation

### Prerequisites

- C++17 compatible compiler (g++ 7+ or clang 5+)
- POSIX-compliant operating system (Linux, macOS, WSL)

### Build

```bash
git clone https://github.com/pin-toto/sc-pt.git
cd sc-pt
g++ -std=c++17 -O3 -pthread scpt.cpp -o scpt
```

### Quick Install

```bash
sudo cp scpt /usr/local/bin/
```

## Usage

### Basic Syntax

```bash
./scpt <target> [options]
```

### Target Specification

- **IP Address**: `./scpt 192.168.1.1`
- **Hostname**: `./scpt google.com`

### Options

| Option | Description |
|--------|-------------|
| `-p <port>` | Scan a single port |
| `-p <port1,port2,...>` | Scan multiple comma-separated ports |
| `-r <start> <end>` | Scan a port range |
| `-c` | Scan common ports (well-known ports) |
| `-v` | Enable version detection |
| `-t <ms>` | Set timeout in milliseconds (default: 200) |
| `-T <threads>` | Set number of threads (default: 100, max: 1000) |
| `-P` | Show progress indicator |
| `-s` | Silent mode (hide service names) |
| `-h` | Display help message |

### Examples

#### Basic Scans

```bash
# Full port scan (1-65535) on localhost
./scpt 127.0.0.1

# Scan a single port
./scpt 192.168.1.1 -p 80

# Scan multiple ports
./scpt 192.168.1.1 -p 80,443,8080

# Scan a port range
./scpt 192.168.1.1 -r 1 1024

# Scan common ports only
./scpt 192.168.1.1 -c
```

#### Advanced Scans

```bash
# Full scan with version detection
./scpt 192.168.1.1 -v

# Scan specific port with version detection
./scpt 192.168.1.1 -p 22 -v

# Scan with custom timeout and thread count
./scpt 192.168.1.1 -r 1 10000 -t 500 -T 200

# Hostname scan with version detection and progress
./scpt google.com -v -P

# Silent scan (no service names)
./scpt 192.168.1.1 -s
```

## Version Detection

SC-PT can identify service versions for the following ports:

| Port | Service |
|------|---------|
| 22 | SSH |
| 80 | HTTP (Apache, nginx, etc.) |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 5900 | VNC |
| 27017 | MongoDB |
| 8080 | HTTP-Alt (Tomcat, etc.) |
| 8443 | HTTPS-Alt |

### How Version Detection Works

1. **Banner Grabbing**: Connects to open ports and reads service banners
2. **Protocol-Specific Probes**: Sends specialized probes for different services
3. **Response Analysis**: Parses responses to extract version information

## Performance

- **Thread Management**: Intelligent thread pooling with automatic scaling
- **Optimized Scanning**: Non-blocking socket operations with timeout control
- **Memory Efficient**: Minimal memory footprint even for full port scans

### Performance Tips

- Use `-t 100` for faster scans (works best on local networks)
- Use `-T 500` for scanning many hosts simultaneously
- Use `-P` to monitor progress on large scans

## Building for Production

### Production Build

```bash
g++ -std=c++17 -O3 -march=native -pthread scpt.cpp -o scpt
strip scpt
```

### Debug Build

```bash
g++ -std=c++17 -g -pthread scpt.cpp -o scpt-debug
```

## Technical Details

### Architecture

- **ThreadPool**: Custom thread pool for efficient concurrent scanning
- **Non-blocking I/O**: Uses non-blocking sockets with select() for connection monitoring
- **Atomic Operations**: Thread-safe counters and state management
- **Banner Grabbing**: Protocol-specific probes for version detection

### Supported Operating Systems

- Linux (Ubuntu, Debian, CentOS, etc.)
- macOS
- Windows (via WSL)
- Any POSIX-compliant system

## Troubleshooting

### Common Issues

#### "Address already in use" / Permission denied
```bash
# Need root privileges for some ports or scanning
sudo ./scpt 192.168.1.1
```

#### Slow scanning on remote networks
```bash
# Increase timeout for remote scanning
./scpt remote-host.com -t 500
```

#### High CPU usage
```bash
# Reduce thread count
./scpt 192.168.1.1 -T 50
```

#### Version detection not working
- Ensure the target is reachable
- Check if the service responds to protocol-specific probes
- Increase timeout with `-t 500`

## Security Considerations

⚠️ **Legal Disclaimer**: This tool is intended for authorized security testing and network administration only. Unauthorized scanning of networks may be illegal in many jurisdictions.

- Always obtain proper authorization before scanning
- Use responsibly and ethically
- Respect network boundaries and policies

## About

**SC-PT** (Scanr-Pintoto) is developed by [Pintoto](https://github.com/pin-toto). It's designed to be fast, reliable, and user-friendly for network reconnaissance tasks.

## License

This project is open-source software. Feel free to use, modify, and distribute it in accordance with the license.

---

**Author**: [Pintoto](https://github.com/pin-toto)

**Project URL**: [https://github.com/pin-toto/sc-pt](https://github.com/pin-toto/sc-pt)

**Version**: 1.0.0
