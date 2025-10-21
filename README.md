# NebulaProbe

<p align="center">
  <a href="https://github.com/v4nsh0x"><img src="https://img.shields.io/badge/GitHub-%40v4nsh0x-181717?style=for-the-badge&logo=github" alt="GitHub - v4nsh0x"/></a>
</p>

Powerful, terminal-first subdomain enumeration toolkit built for bug bounty hunters and security researchers. Fast, configurable, and designed to be easy to extend.

## Key features

* Certificate enumeration via crt.sh
* Optional wordlist-based brute forcing
* Async DNS resolution with configurable concurrency
* Save output to plain text or JSON
* Minimal, dependency-light implementation
* CLI banner with Nebula/galaxy theme and colors

## Installation

```bash
git clone https://github.com/v4nsh0x/nebula-probe.git
cd nebula-probe
python3 -m pip install -r requirements.txt
```

## Usage

```bash
python3 nebula_probe_cli.py --target example.com --crt --output results.txt
python3 nebula_probe_cli.py -t example.com -c -b -l ~/wordlists/subdomains.txt -w 100 -o results.json
python3 nebula_probe_cli.py -t example.com -b -l ~/wordlists/subs.txt
```

### CLI options

* `--target, -t` TARGET domain (required)
* `--workers, -w` number of concurrent resolver workers (default 50)
* `--wordlist, -l` path to subdomain wordlist
* `--crt, -c` query crt.sh for certificate records
* `--bruteforce, -b` run wordlist brute-force
* `--output, -o` save results to file (txt or json)

## Examples

Query crt.sh and resolve discovered hosts:

```bash
python3 nebula_probe_cli.py -t example.com -c -o example.txt
```

Run crt.sh and brute-force with a wordlist and 100 workers, save JSON:

```bash
python3 nebula_probe_cli.py -t example.com -c -b -l ~/wordlists/subs.txt -w 100 -o results.json
```

## Output format

* Plain text: one host per line; resolved IPs appended after a space
* JSON: array of objects with `host` and `ips` fields

## Ethics

Only use NebulaProbe on targets you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

## Contributing

PRs and forks welcome. If you add new enumeration sources or integrations (e.g., VirusTotal, SecurityTrails), include configuration toggles and keep dependencies optional.

## Acknowledgements

Named and packaged by Vansh Saxena (`v4nsh0x`).
