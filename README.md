# Reclaim

is a Go-based tool to identify potential subdomain takeover vulnerabilities by checking CNAME records and verifying exploitability through HTTP responses

## Features

- **CNAME Resolution**: Identifies CNAME records for subdomains.
- **Exploitability Check**: Verifies if the resolved CNAME points to an external service and is vulnerable to takeover.
- **Verbose Mode**: Provides detailed output for debugging and analysis.
- **Graceful Shutdown**: Handles interruptions cleanly without leaving hanging goroutines.
- **Customizable Wordlists**: Allows external service and subdomain inputs via text files.
- **Concurrency**: Supports multithreading for faster scans.
- **Wordlist-Based Scanning**: Can define custom wordlists for external services and subdomains, enabling targeted scans.

## Installation

`go install -v github.com/Vulnpire/reclaim@latest`


## Usage

`reclaim -file=subs.txt -wordlist=external.txt <flags>`

### Command-Line Arguments

| Flag         | Description                                              | Default       |
|--------------|----------------------------------------------------------|---------------|
| `-subs`      | File containing subdomains to check                      | Required      |
| `-external`  | File containing external services to check               | Required      |
| `-v`         | Enable verbose output                                    | Disabled      |
| `-c`         | Number of concurrent workers                             | `10`          |
| `-t`         | Timeout for DNS lookups (in seconds)                     | `5`           |
| `-d`         | Delay between requests (in milliseconds)                 | `100`         |
| `-check`     | Validate exploitability of vulnerable services           | Disabled      |

## Example Output:

```
[VULNERABLE] sub.example.com -> s3.amazonaws.com
[SAFE] sub.example2.com -> github.io
[NO CNAME] sub.example3.com
```

## Wordlist-Based Scanning

The tool relies on wordlists for:

1. **Subdomains**: A file containing the subdomains to scan.
2. **External Services**: A file listing external services that could be vulnerable to takeover (e.g., `github.io`, `amazonaws.com`).

### Example Wordlist for External Services (`external.txt`):

```
s3.amazonaws.com
github.io
herokuapp.com
myshopify.com
domains.tumblr.com
wordpress.com
zendesk.com
bitbucket.io
cargo.site
desk.com
fastly.net
ghost.io
helpscoutdocs.com
custom.intercom.help
azurewebsites.net
readme.io
surge.sh
unbouncepages.com
webflow.io
wpengine.com
```
---

## Comparison to Other Tools

| Feature                      | This Tool              | Other Tools |
|------------------------------|------------------------|---------------------------------------|
| **CNAME Detection**          | Yes                    | Yes                                   |
| **Exploitability Check**     | Yes (`-check` flag)    | Partial or None                       |
| **Custom External Services** | Yes                    | Limited                               |
| **Concurrency Control**      | Yes (`-c` flag)        | Yes                                   |
| **Rate Limiting**            | Yes (`-d` flag)        | Limited                               |
| **Cross-Platform**           | Yes (Go-based)         | Varies                                |

---

## Enhancements

Planned improvements for future releases:

1. **Integration with APIs**:
   - Fetch additional subdomain data from third-party services like Shodan.
2. **Reporting**:
   - Generate detailed reports in JSON or CSV formats for automation and analysis.
3. **Advanced Response Analysis**:
   - Use heuristic-based methods to identify new vulnerable patterns.
4. **Service-Specific Exploitation**:
   - Automate exploitation for specific services (e.g., claiming S3 buckets or GitHub Pages).

## Axiom Support

```
» cat ~/.axiom/modules/reclaim.json

[{
        "command":"reclaim -file input -wordlist ~/lists/external.txt | anew output",
        "ext":"txt"
}]
```

## Disclaimer

This tool is intended for educational and ethical testing purposes only. Unauthorized use against third-party systems is strictly prohibited.
