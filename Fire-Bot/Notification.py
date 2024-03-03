import time
from winotify import Notification, audio

toast = Notification (app_id="Fire-Bot",
                     title="Alert",
                     msg="SQL Injection",
                     duration="short",
                     icon="E:\Organixed_Bot\static\img\chat-icon.chat-icon.jpeg")


toast.set_audio(audio.Default,loop=False)

toast.add_actions(label="Prevent",launch="http://127.0.0.1:5000/")
toast.show()




