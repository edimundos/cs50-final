from flask import render_template, session
import requests
import json

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def call_api(method, body):
    URL = f"https://tyrian-throats.000webhostapp.com/{method}.php"
    #URL = f"https://tyrian-throats.000webhostapp.com/get_all_users.php"
    #headers = {'Content-Type': 'application/json'}

    rows = requests.post(URL, data=body, json=body)
    if rows.status_code == 200:
        print(rows.text)
        return rows.text
    else:
        return rows.status_code
    
def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function