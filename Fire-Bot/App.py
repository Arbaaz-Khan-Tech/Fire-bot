from flask import Flask,render_template,request,redirect
import re
import time
from winotify import Notification, audio

app = Flask(__name__)

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