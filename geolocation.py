import requests

def get_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        city = data.get("city", "")
        region = data.get("region", "")
        country = data.get("country", "")
        return f"{city}, {region}, {country}".strip(", ")
    except Exception as e:
        print(f"Error fetching geolocation for {ip_address}: {e}")
        return "Unknown Location"
