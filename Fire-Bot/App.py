from flask import Flask,render_template,request,redirect
import re
import time
from winotify import Notification, audio
from flask import Flask, request, jsonify,render_template
import google.generativeai as genai
import random
import string
import IP_Search
import Domain_Search
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



app = Flask(__name__)



def process_input(user_input):
    # Process user input here
    return "You said: " + user_input  # For demonstration purposes, echo back the recognized text





logging.basicConfig(filename='user_input.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def process_input(user_input):
    # Log the user input
    logging.info(f"User Input: {user_input}")


app = Flask(__name__,static_url_path='/static')


def get_api_key():
    # Load API key from config.json
    with open('config.json') as json_file:
        data = json.load(json_file)
        return data.get('x-apikey')

# Read API key from config.json
xapi_key = get_api_key()



def get_api_key():
    # Load API key from config.json
    with open('config.json') as json_file:
        data = json.load(json_file)
        return data.get('api_key')

# Read API key from config.json
api_key = get_api_key()

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
            return render_template('signin.html', error='No file pachat_interface')
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

model = genai.GenerativeModel(
    model_name="gemini-pro",
    generation_config=generation_config,
    safety_settings=safety_settings
)

# Function to generate password
def generate_password(username):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

# Function to generate AI response
def generate_ai_response(user_input):
    response = model.generate_content([user_input])
    return "AI: " + response.text

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
    elif user_input.lower() == "generate password for me":
        username = input("Enter your username: ")  # Modify this for web input
        password = generate_password(username)
        return "Generated password: " + password
    elif user_input.lower() == "check network traffic":
        Network_Traffic_Capture.perform_capture()
        return "Network traffic captured"
    elif user_input.lower() == "quit":
        return "Exiting chatbot"
    elif user_input.lower() == "file scan":
        file_path = input("Enter the path of the file to be scanned: ")  # Modify this for web input
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
        return render_template('index.html')
    elif any(suspicious_pattern in username or suspicious_pattern in password for suspicious_pattern in ["'", "''", 'select', 'OR 1=1', 'AND 1=1', 'DROP TABLE', 'UNION SELECT', 
                           'INSERT INTO', 'UPDATE SET', 'DELETE FROM', 'TRUNCATE TABLE', '--', '/*']):
        # Notify about potential SQL injection attempt
        toast = Notification (
            app_id="Fire-Bot",
            title="Fire-Bor",
            msg="SQL Injection",
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




@app.route("/index")
def index():
    return render_template('index.html')


    



app.run(debug=True)