from flask import Flask,render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template('index.html')

@app.route("/about")
def about():
    
    return render_template('about.html')   #The first name is for html and second one is for this side

@app.route("/blog")
def blog():
    
    return render_template('blog.html')  


@app.route("/contact")
def contact():
    
    return render_template('contact.html')  

@app.route("/detail")
def detail():
    
    return render_template('detail.html')  



@app.route("/price")
def price():
    
    return render_template('price.html')  



@app.route("/service")
def service():
    
    return render_template('service.html')  



@app.route("/team")
def team():
    
    return render_template('team.html')  



@app.route("/testimonial")
def testimonial():
    
    return render_template('testimonial.html')  










app.run(debug=True)
