import google.generativeai as genai
import random
import string
import IP_Search
import Domain_Search
import Camera_Check
import Network_Traffic_Capture 
import time
from File_Scan import scan_file_with_defender
import encryption
import Decryption
import creds
import json




def get_api_key():
    # Load API key from config.json
    with open('config.json') as json_file:
        data = json.load(json_file)
        return data.get('api_key')

# Read API key from config.json
api_key = get_api_key()



# Configure the generative AI model
genai.configure(api_key=api_key)

# Set up the generative model
generation_config = {
    "temperature": 0.9,
    "top_p": 1,
    "top_k": 1,
    "max_output_tokens": 2048,
}

safety_settings = [
    {
        "category": "HARM_CATEGORY_HARASSMENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_HATE_SPEECH",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
    {
        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
    },
]


def handle_decryption_command():
    decryption_key = input("Enter the decryption key: ")
    decrypted_message = encryption.handle_decryption(decryption_key)
    print("Decrypted message:", decrypted_message)


model = genai.GenerativeModel(
    model_name="gemini-pro",
    generation_config=generation_config,
    safety_settings=safety_settings
)

# Main function definition
def main():
    while True:
        user_input = input("You: ")
        response = process_input(user_input)
        print(response)

def process_input(user_input):
    if user_input.lower() == "help":
        return print_help_messages()
    elif user_input.lower() == "camera check":
        camera_check_result = Camera_Check.check_camera_status()
        if camera_check_result:
            return "Camera is ON"
        else:
            return "Camera is OFF"
    elif user_input.endswith(".com") or user_input.endswith(".net") or user_input.endswith(".org"):
        domain_search_result = Domain_Search.search_domain(user_input)
        return domain_search_result
    elif user_input.lower() == "generate password for me":
        username = input("Enter your username: ")
        password = generate_password(username)
        return "Generated password: " + password
    elif user_input.lower() == "encrypt":
            encryption.handle_encryption()  
    elif user_input.lower() == "decrypt":
        handle_decryption_command()          
    elif user_input.lower() == "check network traffic":
        Network_Traffic_Capture.perform_capture()
        return "Network traffic captured"
    elif user_input.lower() == "quit":
        return "Exiting chatbot"
    elif user_input.lower() == "file scan":
        file_path = input("Enter the path of the file to be scanned: ")
        scan_result = scan_file_with_defender(file_path)
        return scan_result
    else:
        if user_input.count('.') == 3:
            ip_search_result = IP_Search.search_ip(user_input)
            if isinstance(ip_search_result, dict):
                return "IP Geolocation Info: " + str(ip_search_result)
            else:
                return "IP Geolocation Info: " + ip_search_result
        else:
            return generate_ai_response(user_input)

# Function to generate AI response
def generate_ai_response(user_input):
    response = model.generate_content([user_input])
    return "AI: " + response.text

# Function to print help messages
def print_help_messages():
    help_messages = {
        "1)": "Check network traffic: Type 'check network traffic' to analyze network traffic and generate a report.",
        "2)": "Camera check: Type 'camera check' to check if the camera is on or off.",
        "3)": "Generate password: Type 'generate password for me' to generate a password based on your username.",
        "4)": "Check IP Address: Type the IP address to retrieve its geolocation information.",
        "5)": "Scan File : Type 'File scan' to scan file for malware and virus.",
        "7)": "Quit: Type 'quit' to exit the program."
    }
    return "\n".join(f"{command}: {description}" for command, description in help_messages.items())

# Entry point of the program
if __name__ == "__main__":
    main()
