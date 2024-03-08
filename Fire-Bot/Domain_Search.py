
# Inside Domain_Search.py

import requests
import json 

def get_api_key():
    # Load API key from config.json
    with open(r'config.json') as json_file:
        data = json.load(json_file)
        return data.get('x-apikey')

# Read API key from config.json
api_key = get_api_key()

def search_domain(domain_name):
    """
    Function to perform a domain search.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain_name}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key  # Replace "Api-Key" with your actual API key
    }
    response = requests.get(url, headers=headers)
    return response.text  # Assuming you want to return the response text
