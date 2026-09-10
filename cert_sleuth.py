import argparse
import re
import sys

import requests

__version__ = "1.0.0"

# Labels: letters/digits/hyphens; no leading/trailing hyphen; at least one dot (e.g. example.com).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain):
    """Normalize and validate a domain. Returns (clean_domain, error)."""
    if domain is None:
        return None, "Domain is required."

    clean = domain.strip().lower()

    # Strip a trailing dot (FQDN style: example.com.)
    if clean.endswith("."):
        clean = clean[:-1]

    if not clean:
        return None, "Domain cannot be empty."

    if "://" in clean or "/" in clean or " " in clean:
        return None, "Pass a bare domain (e.g. example.com), not a URL or path."

    if clean.startswith("*."):
        return None, "Wildcards are not allowed; pass the base domain (e.g. example.com)."

    if not _DOMAIN_RE.match(clean):
        return None, f"Invalid domain: {domain!r}"

    return clean, None


def fetch_certificates(domain):
    """Query crt.sh for CT log entries matching a domain and its subdomains.

    Returns a tuple of (certificates, error). On success, error is None.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return [], "Received unexpected data format from crt.sh."
        return data, None
    except requests.Timeout:
        return [], "Request timed out while contacting crt.sh."
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return [], f"crt.sh returned HTTP {status}."
    except requests.RequestException:
        return [], "Network error while contacting crt.sh."
    except ValueError:
        return [], "Received invalid JSON from crt.sh."


def parse_subdomains(raw_json):
    """Extract unique, cleaned hostnames from crt.sh certificate entries."""
    subdomains = set()

    for entry in raw_json:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:
                subdomains.add(name)

    return sorted(subdomains)


def filter_subdomains(subdomains, domain):
    """Keep only hostnames that belong to the target domain."""
    domain = domain.strip().lower()
    return sorted(
        name for name in subdomains
        if name == domain or name.endswith(f".{domain}")
    )


def save_subdomains(subdomains, output_path):
    """Write subdomains to a file, one hostname per line."""
    with open(output_path, "w", encoding="utf-8") as f:
        if subdomains:
            f.write("\n".join(subdomains) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains via Certificate Transparency logs (crt.sh)."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "-o", "--output",
        help="Save results to a file (one subdomain per line)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show certificate and hostname counts at each pipeline stage",
    )
    args = parser.parse_args()

    domain, validation_error = validate_domain(args.domain)
    if validation_error:
        print(f"[!] {validation_error}", file=sys.stderr)
        raise SystemExit(2)

    print(f"[*] Querying crt.sh for {domain}...", file=sys.stderr)

    raw, error = fetch_certificates(domain)
    if error:
        print(f"[!] {error}", file=sys.stderr)
        raise SystemExit(1)

    parsed = parse_subdomains(raw)
    subdomains = filter_subdomains(parsed, domain)

    if args.verbose:
        print(f"[*] crt.sh returned {len(raw)} certificate entries.", file=sys.stderr)
        print(
            f"[*] Extracted {len(parsed)} unique hostnames before domain filtering.",
            file=sys.stderr,
        )
        print(
            f"[*] {len(subdomains)} hostnames matched {domain}.",
            file=sys.stderr,
        )

    if not subdomains:
        print(f"[*] No subdomains found for {domain}.", file=sys.stderr)
    else:
        print(f"Found {len(subdomains)} unique subdomains for {domain}:\n")
        for subdomain in subdomains:
            print(subdomain)

    if args.output:
        save_subdomains(subdomains, args.output)
        print(f"[*] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()