# cert_sleuth

A small Certificate Transparency (CT) reconnaissance tool. It queries [crt.sh](https://crt.sh/) for publicly logged TLS certificates, extracts hostnames, deduplicates them, and filters results to the target domain.

Built step-by-step to learn how CT-based subdomain enumeration works under the hood.

## How Certificate Transparency recon works

When a Certificate Authority issues a TLS certificate, it is usually published to public **Certificate Transparency logs**. Search engines like crt.sh index those logs.

Because certificates list the hostnames they cover (Common Name and Subject Alternative Names), querying CT for a domain often reveals:

- Subdomains you did not know about (`api.example.com`, `staging.example.com`)
- Historical names that may still resolve
- Hostnames from multi-SAN certificates that also mention unrelated domains (noise)

`cert_sleuth` turns that into a clean list:

1. **Fetch** — query `crt.sh` with `q=%.domain` and `output=json`
2. **Parse** — split `name_value` fields (sometimes newline-separated), lowercase, drop wildcards
3. **Deduplicate** — unique hostnames via a set
4. **Filter** — keep only names that are the domain or end with `.{domain}`
5. **Output** — print to stdout and optionally save to a file

## Requirements

- Python 3.9+
- Network access to `crt.sh`

## Install

```bash
git clone <your-repo-url> cert_sleuth
cd cert_sleuth

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python cert_sleuth.py example.com

# Save results (one hostname per line)
python cert_sleuth.py example.com -o results.txt

# Verbose pipeline stats on stderr
python cert_sleuth.py example.com -v

# Show version
python cert_sleuth.py --version

# Combine flags
python cert_sleuth.py example.com -v -o results.txt
```

Status and error messages go to **stderr**. Hostname results go to **stdout**, so you can pipe cleanly:

```bash
python cert_sleuth.py example.com 2>/dev/null | head
```

### CLI options

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (required), e.g. `example.com` |
| `-o`, `--output` | Write results to a file |
| `-v`, `--verbose` | Show cert/hostname counts at each stage |
| `--version` | Print version and exit |
| `-h`, `--help` | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (including “no subdomains found”) |
| `1` | Network / crt.sh failure |
| `2` | Invalid domain input |

## Tests

Offline unit tests cover validation, parsing, filtering, and file output (no network):

```bash
python -m unittest test_cert_sleuth.py -v
```

## Project structure

```
cert_sleuth/
├── cert_sleuth.py         # CLI and CT pipeline
├── test_cert_sleuth.py    # Offline unit tests
├── requirements.txt       # Python dependencies
└── README.md
```

## Notes and limitations

- crt.sh can be slow or rate-limit under load; timeouts are handled, but retries are not implemented yet.
- CT data is historical: a hostname in a cert may no longer be live.
- Multi-SAN certificates introduce unrelated hostnames; domain filtering reduces that noise but is not perfect for every edge case.
- Use only against domains you are authorized to assess.

## License

Add a license of your choice when you publish the project.
