

import requests

def reverse_phone_lookup(phone_number):
    api_key = "0MMWoMFRD7xa48fRKOAN2LLbQofI1jpT"  # Replace "YOUR_API_KEY" with your actual API key
    api_url = f"https://www.ipqualityscore.com/api/json/phone/{api_key}/{phone_number}"
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
        
        data = response.json()
        if data["success"]:
            if data["valid"]:
                print(f"The phone number {phone_number} is valid.")
                if data["carrier"]:
                    print(f"Carrier: {data['carrier']}")
                else:
                    print("Carrier information not available.")
                if data["line_type"]:
                    print(f"Line type: {data['line_type']}")
                else:
                    print("Line type information not available.")
            else:
                print(f"The phone number {phone_number} is invalid.")
        else:
            print("API request failed:", data.get("message"))
    except requests.exceptions.RequestException as e:
        print("Error making API request:", e)

# Example phone number for reverse lookup
phone_number = "+91 9029841937"   # Replace with the phone number for reverse lookup

# Call the function to perform reverse phone lookup
reverse_phone_lookup(phone_number)
