from flask import Flask,render_template,request,redirect,session,url_for
import re
import time
from winotify import Notification, audio
from flask import Flask, request, jsonify,render_template
import google.generativeai as genai
import random
import string
import IP_Search
import Domain_Search
import Log_Analyse
import Camera_Check
import Network_Traffic_Capture 
from File_Scan import scan_file_with_defender
import logging
from cryptography.fernet import Fernet
import json
import requests
from urllib.parse import urlparse
import pytesseract
import PIL.Image
import cv2
import time
from PIL import Image
from urllib.parse import urlparse
import io
from winotify import Notification,audio
import speech_recognition as sr
from datetime import datetime
from notify_run import Notify
import Brute_Detection
import psutil
import socket
import sys
import colorama
from time import sleep

notify = Notify()





app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


def process_input(user_input):
    # Process user input here
    return "You said: " + user_input  # For demonstration purposes, echo back the recognized text


def scan_ports(host, port_range):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Adjust the timeout as needed
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def count_tabs(app_name):
    count = 0
    for proc in psutil.process_iter(['pid', 'name']):
        if app_name.lower() in proc.info['name'].lower():
            count += 1
    return count

def terminate_excess_tabs(app_name, target_count):
    current_count = count_tabs(app_name)
    excess_count = current_count - target_count
    if excess_count > 0:
        for proc in psutil.process_iter():
            if app_name.lower() in proc.name().lower():
                proc.terminate()
                excess_count -= 1
                if excess_count == 0:
                    break





logging.basicConfig(filename='user_input.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def process_input(user_input):
    # Log the user input
    logging.info(f"User Input: {user_input}")


app = Flask(__name__,static_url_path='/static')


def get_api_key():
    # Load API key from config.json
    with open(r'E:\Fire-bot\Fire-Bot\config.json') as json_file:
        data = json.load(json_file)
        return data.get('x-apikey')

# Read API key from config.json
xapi_key = get_api_key()



def get_api_key():
    # Load API key from config.json
   with open(r'E:\Fire-bot\Fire-Bot\config.json') as json_file:
        data = json.load(json_file)
        return data.get('api_key')

# Read API key from config.json
api_key = get_api_key()




colorama.init()

def type(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

  # Scan using multiple AV start

def scan_file_with_virustotal(file_path):
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    api = open("E:\\Fire-bot\\Fire-Bot\\vt-api.txt", "r").read()
    params = {"apikey": api}
    file_to_upload = {"file": open(file_path, "rb")}
    response = requests.post(url, files=file_to_upload, params=params)
    file_url = f"https://www.virustotal.com/api/v3/files/{response.json()['sha1']}"
    headers = {"accept": "application/json", "x-apikey": api}
    type(colorama.Fore.YELLOW + "Analysing....")
    response = requests.get(file_url, headers=headers)
    report = response.text
    report = json.loads(report)
    name = report["data"]["attributes"].get("meaningful_name", "unable to fetch")
    hash_value = report["data"]["attributes"]["sha256"]
    description = report["data"]["attributes"]["type_description"]
    size = report["data"]["attributes"]["size"] * 10**-3
    result = report["data"]["attributes"]["last_analysis_results"]
    print()
    type((colorama.Fore.WHITE + "Name : ", colorama.Fore.YELLOW + f"{name}"))
    type((colorama.Fore.WHITE + "Size : ", colorama.Fore.YELLOW + f"{size} KB"))
    type((colorama.Fore.WHITE + "Description : ", colorama.Fore.YELLOW + f"{description}"))
    type((colorama.Fore.WHITE + "SHA-256 Hash : ", colorama.Fore.YELLOW + f"{hash_value}"))
    malicious_count = 0
    print()
    for key, values in result.items():
        key = colorama.Fore.WHITE + f'{key}'
        verdict = values['category']
        if verdict == 'undetected':
            verdict = colorama.Fore.GREEN + 'undetected'
        elif verdict == 'type-unsupported':
            verdict = colorama.Fore.RED + 'type-unsupported'
        elif verdict == 'malicious':
            malicious_count += 1
            verdict = colorama.Fore.RED + 'malicious'
        else:
            verdict = colorama.Fore.RED + f'{verdict}'
        str = f'{key}: {verdict}'
        type(str)
        print()
    if malicious_count != 0:
        type(colorama.Back.WHITE + colorama.Fore.RED + f'\t\t\t\t{malicious_count} antivirus found the given file malicious !!')
    elif malicious_count == 0:
        type(colorama.Back.WHITE + colorama.Fore.GREEN + f'\t\t\t\t No antivirus found the given file malicious !!')
    print(colorama.Back.BLACK + ' ')



    # Scan using multiple AV end
#Scan url

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Function to scan a URL using VirusTotal API
def scan_url(url):
    # Your VirusTotal API key
    api_key = xapi_key
    # VirusTotal API endpoint for URL scanning
    url_scan_endpoint = f"https://www.virustotal.com/api/v3/urls/{url}"
    # Headers for the API request
    headers = {
        "x-apikey": api_key
    }
    # Send a GET request to scan the URL
    response = requests.get(url_scan_endpoint, headers=headers)
    # Return the response JSON data
    return response.json()

# Configure the generative AI model
genai.configure(api_key=api_key)



@app.route('/', methods=['GET', 'POST'])
def ocr():
    if request.method == 'POST':
        # Check if the POST request has the file part
        if 'file' not in request.files:
            return render_template('chat_interface.html', error='No file pachat_interface')
        file = request.files['file']
        # If user does not select file, browser also submit an empty part without filename
        if file.filename == '':
            return render_template('signin.html', error='No selected file')

        if file:
            # Read the uploaded image file
            img = Image.open(io.BytesIO(file.read()))
            # Perform OCR on the image to extract text
            text = pytesseract.image_to_string(img)

            # Check if the extracted text contains a URL
            for word in text.split():
                if is_valid_url(word):
                    # If a URL is found in the text, scan it using VirusTotal API
                    scan_result = scan_url(word)
                    if scan_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0) == 0:
                        # If the URL is not safe (has no harmless scans), create a notification
                        toast = Notification(app_id="Fire-Bot",
                                             title="Alert",
                                             msg="Unsafe URL Detected",
                                             duration="short",
                                             icon="E:\Organixed_Bot\static\img\chat-icon.chat-icon.jpeg")
                        # Set audio for the notification
                        toast.set_audio(audio.Default, loop=False)
                        # Show the notification
                        toast.show()
                        break  # Break out of loop after detecting unsafe URL

            return render_template('signin.html', text=text)
    return render_template('signin.html')



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

model = genai.GenerativeModel(model_name="gemini-pro")
chat = model.start_chat(history=[])


# Function to generate password
def generate_password(username):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

# Function to generate AI response
def generate_ai_response(user_input):
    response = model.generate_content([user_input])
    # Check if the response is a JSON response
    if isinstance(response, dict):
        # Assume it's a JSON response
        # Extract the text from the JSON response
        text = response.get('text', '')  # Adjust this based on the actual structure of the JSON response
        return " " + text
    else:
        # Assume it's a plain text response
        return " " + response.text

# Function to process user input
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

    elif user_input.lower() == "check network traffic":
        Network_Traffic_Capture.perform_capture()
        return "Network traffic captured"
    elif user_input.lower() == "quit":
        return "Exiting chatbot"
    elif user_input.lower() == "file scan":
        file_path = input("Enter the path of the file to be scanned: ")  # Modify this for web input
        scan_result = scan_file_with_defender(file_path)
        return scan_result
    if user_input.lower() == "multiple_av_scan":
        file_path = input("Enter the path of the file to be scanned: ")
        scan_file_with_virustotal(file_path)  
        result = "File Scanned Succesully"
        return result
          

    elif user_input.lower() == "generate password for me":
        username = input("Enter your username: ")  # Modify this for web input
        password = generate_password(username)
        return "Generated password: " + password
    elif user_input.lower() == "analyze log":
        log_file_path = "E:\\Fire-bot\\Fire-Bot\\Net_Log.txt"
        threat_detected = Log_Analyse.analyze_log_file(log_file_path)
        if threat_detected:
            return "Threat detected! Take necessary action. Login after 8 pm and malicious IP detected"
        else:
            return "No threat detected."
    elif user_input.lower() == "bruteforce log":
        log_entries_file = "E:\\Fire-bot\\Fire-Bot\\Login._Log.json"
        brute_force_attacks = Brute_Detection.detect_brute_force_attacks(log_entries_file)
        if brute_force_attacks:
            response = "Brute force attacks detected:\n"
            for attack in brute_force_attacks:
                response += f"Timestamp: {attack[0]}, IP Address: {attack[1]}\n"
            return response
    elif user_input.lower() == "simulation":
    # This block will only execute when user_input is "simulation"
      result = "Type 'phishing_email', 'urgent_phone_call', 'fake_website', or 'pretexting_call'"
      return result

    elif user_input.lower() == "phishing_email":
        result = "Imagine you receive an email with the subject line Urgent Action Required: Verify Your Account.  The email appears to be from your bank and claims suspicious activity on your accoun It includes a link asking you to 'log in and confirm your details immediately. What would you do? Reply with 'click_the_link' or 'verify_mail'"   
        return result
    elif user_input.lower() == "click_the_link":    
        result = "Uh oh! Clicking the link could lead to a fake website designed to steal your login credentials. Always verify the email's authenticity before clicking any links."
        return result 
    elif user_input.lower() == "verify_mail": 
        result = "Great job! Here are some tips for verifying email legitimacy Check the sender's email address for typos or inconsistencies with your bank's official domain. Hover over the link to see the actual destination URL before clicking. Contact your bank directly using a phone number you know is correct, not one provided in the email."    
        return result
    elif  user_input.lower() == "urgent_phone_call":
     result = """Imagine you receive a call from someone claiming to be from your internet service provider (ISP).
They claim there's a critical issue with your account and that your internet will be shut down if you don't act immediately.
They ask you to download a remote access tool to 'fix the problem.'
What would you do? (Reply with 'download_the_tool' or 'verify_caller')"""
     return result

    elif user_input.lower() == "port scan":
          host = 'localhost'  # or '127.0.0.1'
          start_port = int(input("Enter the starting port: "))
          end_port = int(input("Enter the ending port: "))
          open_ports = scan_ports(host, (start_port, end_port))
          if open_ports:
            return open_ports
            for port in open_ports:
             return port 
          else:
            print("No open ports found.")

    elif user_input.lower() == "terminate":
        app_name = "notepad.exe"
        target_count = 3  # Desired number of tabs
        terminate_excess_tabs(app_name, target_count)
        result = "Excess tabs terminated."
        return result


    elif user_input.lower() == "download_the_tool":
     result = "Uh oh! Downloading an unknown tool could grant the caller remote access to your computer, allowing them to steal your data or install malware. Never download software from unsolicited sources."
     return result

    elif user_input.lower() == "verify_caller":
      result = """Excellent! Here's how to verify the caller's identity:
- Ask for their name and employee ID.
- Tell them you'll call them back at a phone number you know is genuine (look it up on your ISP's website).
- Don't give out any personal information or download anything until you've confirmed their legitimacy."""
      return result
    elif  user_input.lower() == "fake_website":
     result = """Imagine you're searching online for a popular software download.
You find a website with a familiar-looking logo and download the software.
What's a potential consequence of this action? (Reply with 'malware_infection' or 'data_theft')"""
     return result
    elif  user_input.lower() == "malware_infection":
        result = "Correct! The website could be fake, and the downloaded software might be infected with malware that steals your data or harms your computer"
        return result
    elif  user_input.lower() == "data_theft":
        result = "Both malware infection and data theft are potential consequences. Always download software from trusted sources, like the official website of the software provider."
        return result
    elif  user_input.lower() == "pretexting_call":
        result = "Imagine you receive a call from someone claiming to be from your credit card company.The caller asks for your credit card number for 'verification purposes.' What would you do? (Reply with 'provide_number' or 'refuse'"
        return result 
    elif  user_input.lower() == "provide_number":
        result = "Be cautious! Providing sensitive information over the phone, especially in response to unsolicited calls, can lead to identity theft or financial fraud."
        return result
    elif  user_input.lower() == "refuse":
        result = "Good decision! It's wise to refuse providing sensitive information over the phone, especially if you're unsure of the caller's identity."
        return result        
    elif  user_input.lower() == "who_created_you":
        result = "I was created by team Cyber Squad"
        return result          

    elif user_input.lower() == "what is malware":
      result = """Malware, short for malicious software, refers to any intrusive software developed by cybercriminals (often called hackers) to steal data and damage or destroy computers and computer systems. Examples of common malware include viruses, worms, Trojan viruses, spyware, adware, and ransomware. Recent malware attacks have exfiltrated data in mass amounts"""
      return result

    elif user_input.lower() == "what is virus":
      result = """A computer virus is a type of program that, much like a regular virus, attaches itself to a host with the intention of multiplying and spreading its infection further. Computer viruses can be created by anyone with the proper skill set, from individuals to major organizations, and can infect computers, smartphones, tablets, and even smart cars."""
      return result 
    

    else:
        if user_input.count('.') == 3:
            ip_search_result = IP_Search.search_ip(user_input)
            if isinstance(ip_search_result, dict):
                return "IP Geolocation Info: " + str(ip_search_result)
            else:
                return "IP Geolocation Info: " + ip_search_result
        else:
            return generate_ai_response(user_input)

# Function to print help messages
def print_help_messages():
    help_messages = {
        "1)": "Check network traffic: Type 'check network traffic' to analyze network traffic and generate a report.",
        "2)": "Camera check: Type 'camera check' to check if the camera is on or off.",
        "3)": "Generate password: Type 'generate password for me' to generate a password based on your username.",
        "4)": "Check IP Address: Type the IP address to retrieve its geolocation information.",
        "5)": "Scan File : Type 'file scan' to scan file for malware and virus.",
        "6)": "Quit: Type 'quit' to exit the program."
    }
    return jsonify(help_messages)




@app.route('/chat', methods=['POST'])
def chat():
    # Check if the request contains JSON data with 'input' key
    if 'input' in request.json:
        # Get the user input from the JSON data
        user_input = request.json.get('input')
        return jsonify({'response': process_input(user_input)})

    # If JSON data with 'input' key is not found, try to recognize speech input
    recognizer = sr.Recognizer()

    # Use the microphone as the audio source
    with sr.Microphone() as source:
        print("Say something:")
        recognizer.adjust_for_ambient_noise(source)
        audio = recognizer.listen(source)

    try:
        # Use the recognizer to convert audio to text
        user_input = recognizer.recognize_google(audio)
        print("Recognized:", user_input)
        return jsonify({'response': process_input(user_input)})
    except sr.UnknownValueError:
        return jsonify({'response': "Sorry, I could not understand what you said."})
    except sr.RequestError as e:
        return jsonify({'response': "Could not request results; {0}".format(e)})


@app.route("/")
def helloworld():
    return render_template('signin.html')
valid_username = 'FireBot@gmail.com'
valid_password = '123'

 

@app.route('/signin', methods=['POST'])
def signin():
    username = request.form.get('username')
    password = request.form.get('password')
   

    if username == valid_username and password == valid_password:
        # Successful login, redirect to a success page
        print("Successful login. Redirecting to service.html.")
        current_hour = datetime.now().hour
        if current_hour >= 11:              # office hour 
            notify.send("Somebody Logged In After Office Hour!")
            print("View your notifications at: ", notify.register())
        return render_template('index.html')
    elif any(suspicious_pattern in username or suspicious_pattern in password for suspicious_pattern in ["'", "''", 'select', 'OR 1=1', 'AND 1=1', 'DROP TABLE', 'UNION SELECT', 
                           'INSERT INTO', 'UPDATE SET', 'DELETE FROM', 'TRUNCATE TABLE', '--', '/*']):
        # Notify about potential SQL injection attempt
        toast = Notification (
            app_id="Fire-Bot",
            title="Fire-Bot",
            msg="SQL Injection Detected",
            duration="short",
         icon="E:\Organixed_Bot\static\img\chat-icon.chat-icon.jpeg"
        )

        toast.set_audio(audio.Mail,loop=False)
        toast.show()
        
        # Redirect back to the signin page with an error message
        return render_template('signin.html', error="Potential SQL injection attempt detected. Please try again.")
    else:
        # Failed login, redirect back to the signin page with an error message
        print("Failed login. Redirecting to contact.html.")
        return render_template('signin.html')

@app.route("/about.html")
def about():
    
    return render_template('about.html')   #The first name is for html and second one is for this side

@app.route("/blog.html")
def blog():
    
    return render_template('blog.html')  


@app.route("/contact.html")
def contact():
    
    return render_template('contact.html')  

@app.route("/detail.html")
def detail():
    
    return render_template('detail.html')  



@app.route("/price.html")
def price():
    
    return render_template('price.html')  

@app.route("/chat_interface.html")
def chat_interface():
    
    return render_template('chat_interface.html')  

@app.route("/service.html")
def service():
    
    return render_template('service.html')  



@app.route("/team.html")
def team():
    
    return render_template('team.html')  



@app.route("/testimonial.html")
def testimonial():
    
    return render_template('testimonial.html') 




@app.route("/index.html")
def index():
    return render_template('index.html')


    




app.run(debug=True)
