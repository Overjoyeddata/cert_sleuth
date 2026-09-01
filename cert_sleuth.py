import argparse

import requests


def fetch_certificates(domain):
    """Query crt.sh for CT log entries matching a domain and its subdomains."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, list) else []
    except (requests.RequestException, ValueError):
        return []


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
    args = parser.parse_args()

    raw = fetch_certificates(args.domain)
    subdomains = filter_subdomains(parse_subdomains(raw), args.domain)

    print(f"Found {len(subdomains)} unique subdomains for {args.domain}:\n")
    for subdomain in subdomains:
        print(subdomain)

    if args.output:
        save_subdomains(subdomains, args.output)
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()