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

def main():
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains via Certificate Transparency logs (crt.sh)."
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    args = parser.parse_args()

    raw = fetch_certificates(args.domain)
    subdomains = parse_subdomains(raw)

    print(f"Found {len(subdomains)} unique subdomains for {args.domain}:\n")
    for subdomain in subdomains:
        print(subdomain)


if __name__ == "__main__":
    main()