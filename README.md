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

## Technical Details

### Authentication

The scanner uses ED25519 cryptographic keys to authenticate with the coordinator:
- On first run, a new keypair is automatically generated and stored in the state directory
- The public key is transmitted during registration
- All results are cryptographically signed before submission

### Scanning Process

The scanner uses Nmap to probe targets with the following characteristics:
- Connect scan (TCP handshake) rather than SYN scanning
- Service version detection
- Basic vulnerability assessment using the "vulners" script
- Banner grabbing for service identification

## Installation

Pre-built binaries are available for Linux, *bsd, macOS, and Windows on the [releases page](https://github.com/fn0rd-io/scanner/releases)

### Building from Source

#### Prerequisites

- Go 1.23 or higher
- Nmap
- Linux/BSD/macOS environment (Windows support limited/untested)

#### Build Steps

```bash
git clone https://github.com/fn0rd-io/scanner.git
cd scanner
go build ./cmd/scanner
```

## Usage

```bash
./scanner
```

### Command-Line Options

- `--coordinator` - URL of the coordinator service (default: "https://coordinator.fn0rd.io")
- `--workers` - Number of concurrent workers (default: 4× CPU cores)
- `--logfile` - Log file path (default: STDOUT)
- `--statedir` - Directory to store state (default: /var/lib/fn0rd)
- `--iface` - Network interface to use for scanning (optional)

### State Directory Structure

The scanner maintains state in the directory specified by `--statedir`:

- `identity` - ED25519 private key in PEM format used to authenticate with the coordinator

## Ethics and Responsible Scanning

This project is committed to ethical internet scanning:

- We perform only non-intrusive scans (TCP connect rather than SYN scans)
- We respect opt-out requests (contact us to be excluded from scanning)
- We follow responsible disclosure for any vulnerabilities found
- We minimize bandwidth usage and system impact with timing controls

### Opting Out

System administrators can opt out of scanning by creating an issue in this repository with the title "Opt-Out Request" and the IP range to exclude.

## Contributing
We welcome contributions from the security community! Whether you can run a scanner node, improve the codebase, or help analyze results, there's a place for you in this project.

### Development

The scanner is written in Go and uses:

- Connect (gRPC) for coordinator communication
- Nmap for service discovery and vulnerability assessment
- ED25519 cryptography for authentication and signing

To contribute code improvements, please submit a pull request with your changes. 
