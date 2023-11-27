from PIL import Image
import base64
from io import BytesIO
from urllib.request import urlopen
import json
from flask import Flask, redirect, render_template, request, session
import bcrypt
from helpers import apology, call_api, login_required
from flask_session import Session

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        user = request.form.get("username")
        pw = request.form.get("password")
        if not user:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not pw:
            return apology("must provide password", 403)
        
        params = {"user": user}
        rows = json.loads(call_api("get_user_by_username", params))
        hashed_pw = rows[0]["password"]
        
        # Ensure username exists and password is correct
        if len(rows) != 1 or not bcrypt.checkpw(pw.encode('utf-8'), hashed_pw.encode('utf-8')):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/myPictures")
@login_required
def myPictures():
    body = {
        "user_id": session["user_id"]
    }
    pictures_bytes = call_api("get_all_pics_by_user", body)
    pictures = []
    for picture_b in pictures_bytes:
        # Decode base64-encoded image
        picture = open("out.jpg", "w")
        picture.write(base64.b64decode(picture_b).decode('base64'))
        picture.close()
        pictures.append(picture)
    return render_template("my_pictures.html", pictures=pictures)
    
@app.route("/uploadMe", methods=["GET", "POST"])
@login_required
def upload_me():
    if request.method == "POST":
        if "file" in request.files:
            image = request.files["file"]
            # Ensure that the file is of an allowed type
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            if '.' in image.filename and image.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                # Save the image
                image.save("venv/static/uploads/self/" + image.filename)
                with open("venv/static/uploads/self/" + image.filename, "rb") as image: #read binary
                    img_string = base64.b64encode(image.read()) 
                body = {
                    "user_id": int(session["user_id"]),
                    "pic": img_string #for BLOB
                }
                call_api("post_picture", body)

            else:
                return apology("Invalid file type. Please upload an image (png, jpg, jpeg)", 400)
                
        return redirect("/")
    else:
        return render_template("upload_me.html")

@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()
    if request.method == "POST":
        # Ensure username was submitted
        pw = request.form.get("password")
        pw2 = request.form.get("confirmation")
        username = request.form.get("username")
        email = request.form.get("email")
        if not username:
            return apology("must provide username", 400)
        
        if not email:
            return apology("must provide email", 400)

        # Ensure password was submitted
        elif not pw or not pw2:
            return apology("must provide password", 400)

        # passwords matchs
        elif not pw == pw2:
            return apology("passwords dont match", 400)

        elif not any(char.isalpha() for char in pw):
            return apology("password must contain at least one letter", 403)

        # Ensure the password contains at least one number
        elif not any(char.isdigit() for char in pw):
            return apology("password must contain at least one number", 403)

        # Ensure the password is at least 8 characters long
        elif len(pw) < 8:
            return apology("password must be at least 8 characters long", 403)
        
        elif "@" not in email:
            return apology("email must contain @", 403)
        
        body = {
            "username": username,
            "pw": pw,
            "email": email,
            "user": username
        }
        
        if len(call_api("get_user_by_username", body)) > 6:
            return apology("username/email already exists", 403)
        
        call_api("post_user", body)
        id = json.loads(call_api("get_user_by_username", body))[0]['id']
        
        
        #IMAGE HANDLING
        if "file" in request.files:
            image = request.files["file"]
            # Ensure that the file is of an allowed type
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            if '.' in image.filename and image.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                # Save the image
                image.save("venv/static/uploads/self/" + image.filename)
                with open("venv/static/uploads/self/" + image.filename, "rb") as image: #read binary
                    img_string = base64.b64encode(image.read()) 
                body = {
                    "user_id": id,
                    "pic": img_string #for BLOB
                }
                call_api("post_picture", body)

            else:
                return apology("Invalid file type. Please upload an image (png, jpg, jpeg)", 400)
        
        
        # Remember which user has logged in
        session["user_id"] = id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=True)