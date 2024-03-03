import pytesseract
import PIL.Image
import cv2
import time
from winotify import Notification, audio

text = pytesseract.image_to_string(PIL.Image.open(r"C:\Users\admin\Desktop\exp2\alter.png"))

if "alice" in text.lower(): 
    toast = Notification(app_id="Fire-Bot",
                         title="Alert",
                         msg="Alice Detected",
                         duration="short",
                         icon="E:\Organixed_Bot\static\img\chat-icon.chat-icon.jpeg")
    
    toast.set_audio(audio.Default, loop=False)  # Move this line inside the 'if' block

    toast.show()  # Properly indented here
       