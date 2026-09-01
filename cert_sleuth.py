import argparse
import sys

import requests


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

    print(f"[*] Querying crt.sh for {args.domain}...", file=sys.stderr)

    raw, error = fetch_certificates(args.domain)
    if error:
        print(f"[!] {error}", file=sys.stderr)
        raise SystemExit(1)

    parsed = parse_subdomains(raw)
    subdomains = filter_subdomains(parsed, args.domain)

    if args.verbose:
        print(f"[*] crt.sh returned {len(raw)} certificate entries.", file=sys.stderr)
        print(
            f"[*] Extracted {len(parsed)} unique hostnames before domain filtering.",
            file=sys.stderr,
        )
        print(
            f"[*] {len(subdomains)} hostnames matched {args.domain}.",
            file=sys.stderr,
        )

    if not subdomains:
        print(f"[*] No subdomains found for {args.domain}.", file=sys.stderr)
    else:
        print(f"Found {len(subdomains)} unique subdomains for {args.domain}:\n")
        for subdomain in subdomains:
            print(subdomain)

    if args.output:
        save_subdomains(subdomains, args.output)
        print(f"[*] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()