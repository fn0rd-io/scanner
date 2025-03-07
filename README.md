# fn0rd.io Scanner

## About

The fn0rd.io Scanner is a distributed internet scanning system designed to index and categorize internet-facing services. This is a **volunteer effort** to help strengthen the global security posture by mapping internet infrastructure, identifying vulnerable systems, and providing actionable intelligence to the security community.

## Mission

Our mission is to create a comprehensive, up-to-date index of internet services that can be used by researchers, security professionals, and system administrators to:

- Identify vulnerable systems before malicious actors can exploit them
- Track the adoption of security practices across the internet
- Provide early warning of emerging threats
- Support academic research into internet security trends

## How It Works

The scanner operates as a distributed system with a central coordinator that assigns scanning tasks to volunteer nodes:

1. Volunteer scanners connect to a coordinator service
2. The coordinator assigns IP ranges to scan
3. Scanners perform non-intrusive probes using Nmap
4. Results are securely sent back to the coordinator for analysis
5. Findings are aggregated and made available to the security community

## Installation

### Prerequisites

- Go 1.19 or higher
- Nmap
- Linux/macOS environment (Windows support limited)

### Building from Source

```bash
git clone https://github.com/fn0rd-io/scanner.git
cd scanner
go build ./cmd/scanner
```

## Usage

```bash
./scanner
```

### Command Line Options

* `--coordinator` - URL of the coordinator service
* `--workers` - Number of concurrent workers (default: 4× CPU cores)
* `--logfile` - Log file path (default: STDOUT)
* `--statedir` - Directory to store state (default: /var/lib/fn0rd)

## Ethics and Responsible Scanning

This project is committed to ethical internet scanning:

* We perform only non-intrusive scans
* We respect opt-out requests
* We follow responsible disclosure for any vulnerabilities found
* We minimize bandwidth usage and system impact

## Contributing

We welcome contributions from the security community! Whether you can run a scanner node, improve the codebase, or help analyze results, there's a place for you in this project.

