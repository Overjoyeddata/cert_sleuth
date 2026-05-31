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
