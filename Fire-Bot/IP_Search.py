# Inside IP_Search.py

import requests

def search_ip(ip_address):
    """
    Function to query the IP geolocation API and return geolocation information.
    """
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
