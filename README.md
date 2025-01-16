# FireBot: Your Comprehensive Cybersecurity Chatbot
Introduction

FireBot is a robust and user-friendly cybersecurity chatbot designed to empower individuals and organizations to navigate the ever-evolving landscape of online security threats. It offers a diverse set of features to protect, detect, and educate users on various cybersecurity concerns, promoting a safer digital experience.

Key Features

Natural Language Interaction and Information Retrieval: Leverages the Gemini API for intuitive conversation flow and delivers relevant security information.
IP Address Analysis: Provides details about an IP address using the ipinfo API, aiding in identifying potential threats or security risks.
URL Scanning: Utilizes the VirusTotal API to scan URLs for malicious content or suspicious activity, safeguarding users from harmful websites.
Camera Detection: Employs the psutil library to detect whether the user's camera is active, raising awareness of potential privacy concerns.
Network Traffic Visualization: Captures network traffic using Scapy and Wireshark for a specified duration and generates a graph (using matplotlib) highlighting the top IP talkers, providing insights into network activity patterns.
Secure Messaging: Encrypts user-entered messages using the CRYPTOJS AES library and stores them securely in a file. Additionally, facilitates decryption of stored messages, ensuring user privacy.
Voice Interaction: Offers convenient voice input capabilities through the speechrecognition library, catering to diverse user preferences.
Password Strength Checker: Evaluates the strength of entered passwords, promoting responsible password management practices.
Image-Based Link Detection: Incorporates OCR technology with the pytesseract library to extract text from images, enabling the verification of suspicious links found within them using VirusTotal, providing an extra layer of protection.
SQL Injection Detection: Identifies potential SQL injection attempts in login pages and generates Windows notifications using the winotify library, alerting users to potential security vulnerabilities.
Installation and Usage

Clone the repository:

Bash
git clone https://github.com/Baazboy77/Fire-bot.git
Use code with caution.
Install dependencies:

Bash
pip install -r requirements.txt
Use code with caution.
Navigate to the project directory:

Bash
cd FireBot
Use code with caution.
Run the chatbot:

Bash
python firebot.py
Use code with caution.
Interact with FireBot using natural language or available commands.

Contributing

We welcome contributions from the community! Please refer to the CONTRIBUTING.md file for guidelines on how to contribute to the project.

## Contact

For any inquiries or support, please contact [Arbaaz](mailto:arbukhan1971@gmail.com) / [Sudarshanxlr8](mailto:Sudarshanxlr8@gmail.com)
## Acknowledgments

We would like to express our sincere gratitude to the following individuals and organizations for their contributions, support, and inspiration in the development of FireBot:

- **[Gemini API](https://example.com/gemini)**: For providing the conversational flow and information retrieval capabilities, which form the backbone of FireBot's interaction with users.
  
- **[IPinfo API](https://example.com/ipinfo)**: For offering valuable IP information retrieval services, enhancing FireBot's functionality in obtaining relevant cybersecurity data.
  
- **[VirusTotal API](https://example.com/virustotal)**: For enabling URL scanning functionality, allowing FireBot to detect and analyze potential threats from URLs.
  
- **[Psutil Python Library](https://example.com/psutil)**: For providing essential system utilities, including the ability to check the camera status, crucial for FireBot's security monitoring capabilities.
  
- **[Scapy](https://example.com/scapy)**: For providing powerful network packet manipulation capabilities, enabling FireBot to capture and analyze network traffic for cybersecurity insights.
  
- **[Wireshark](https://example.com/wireshark)**: For offering advanced network protocol analysis capabilities, enhancing FireBot's network traffic analysis features.
  
- **[Matplotlib](https://example.com/matplotlib)**: For providing versatile plotting capabilities, facilitating the generation of graphs for visualizing network traffic data in FireBot.
  
- **[CryptoJS AES Library](https://example.com/cryptojs)**: For offering robust encryption and decryption capabilities, essential for securing sensitive information handled by FireBot.
  
- **[SpeechRecognition Library](https://example.com/speechrecognition)**: For providing speech recognition functionality, enabling FireBot to accept voice input for user interactions.
  
- **[Pytesseract Library](https://example.com/pytesseract)**: For providing OCR (Optical Character Recognition) capabilities, enabling FireBot to extract text from images for analysis.
  
- **[Winotify Python Library](https://example.com/winotify)**: For offering notification capabilities on Windows systems, crucial for FireBot's alerting functionality.
  

  
We are deeply grateful for the invaluable contributions and resources provided by these individuals and organizations, which have significantly enhanced the functionality and effectiveness of FireBot in cybersecurity operations.
License

This project is made For Fun 

Disclaimer

While FireBot is designed to assist with cybersecurity, it is crucial to remain vigilant and exercise caution when dealing with sensitive information online.
