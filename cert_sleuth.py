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
