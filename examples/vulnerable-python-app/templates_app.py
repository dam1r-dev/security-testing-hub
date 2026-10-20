from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    return render_template("greet.html", name=request.args["name"], title=request.args["title"])  # name is printed with |safe: XSS; title is escaped
