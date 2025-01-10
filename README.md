# Reclaim

is a Go-based tool to identify potential subdomain takeover vulnerabilities by checking CNAME records and verifying exploitability through HTTP responses

## Features

- **CNAME Resolution**: Identifies CNAME records for subdomains.
- **Exploitability Check**: Verifies if the resolved CNAME points to an external service and is vulnerable to takeover.
- **Verbose Mode**: Provides detailed output for debugging and analysis.
- **Graceful Shutdown**: Handles interruptions cleanly without leaving hanging goroutines.
- **Customizable Wordlists**: Allows external service and subdomain inputs via text files.
- **Concurrency**: Supports multithreading for faster scans.

## Installation

`go install -v github.com/Vulnpire/reclaim@latest`


## Usage

reclaim -file=subs.txt -wordlist=external.txt <flags>

## Flags

    -file: Path to the file containing subdomains (required).
    -wordlist: Path to the file containing external services (required).
    -v: Enable verbose output (optional).
    -c: Number of concurrent workers (default: 10).
    -t: Timeout for DNS lookups in seconds (default: 5).
    -d: Delay between requests in milliseconds (default: 100).
    -check: Check exploitability of services (optional, experimental).

## Example Output:

```
[VULNERABLE] sub.example.com -> s3.amazonaws.com
[SAFE] sub.example2.com -> github.io
[NO CNAME] sub.example3.com
```

## Disclaimer

This tool is intended for educational and ethical testing purposes only. Unauthorized use against third-party systems is strictly prohibited.
