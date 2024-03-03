import requests

def check_leaked_password(password):
    api_key = "0MMWoMFRD7xa48fRKOAN2LLbQofI1jpT"  # Replace "YOUR_API_KEY" with your actual API key
    api_url = f"https://www.ipqualityscore.com/api/json/leaked/password/{api_key}/{password}"
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
        
        data = response.json()
        if data["success"]:
            if data["leaked"]:
                print(f"The password has been leaked on the dark web.")
                print(f"Leak sources: {data['leak_sources']}")
            else:
                print(f"The password has not been leaked on the dark web.")
        else:
            print("API request failed:", data.get("message"))
    except requests.exceptions.RequestException as e:
        print("Error making API request:", e)

# Example password to check for leaks
password = "12345678"  # Replace with the password you want to check

# Call the function to check for leaks
check_leaked_password(password)
