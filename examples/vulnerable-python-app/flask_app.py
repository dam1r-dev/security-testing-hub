import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-me-123"


@app.route("/users")
def users():
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # SQL injection
    return {"rows": cur.fetchall()}


@app.route("/users/<int:uid>")
def user_by_id(uid):
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")  # safe: the converter makes uid a number
    return {"rows": cur.fetchall()}


@app.route("/search")
def search():
    q = request.args.get("q", "")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM items WHERE title LIKE %s", ("%" + q + "%",))  # safe: bound parameter
    return {"rows": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args["host"]
    out = subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection
    return out


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"  # reflected XSS


@app.route("/hello-safe")
def hello_safe():
    name = request.args.get("name", "")
    return f"<h1>Hello {escape(name)}</h1>"  # safe


@app.route("/render")
def render():
    return render_template_string("<p>" + request.args.get("t", "") + "</p>")  # template injection


@app.route("/download")
def download():
    return send_file("/srv/files/" + request.args["f"])  # path traversal


@app.route("/download-safe")
def download_safe():
    return send_file("/srv/files/" + secure_filename(request.args["f"]))  # safe


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # insecure deserialization
    cfg = yaml.load(request.form["cfg"])  # insecure deserialization
    return {"ok": bool(obj and cfg)}


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text  # SSRF


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # open redirect


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))  # code injection


def find_user(name):
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()


@app.route("/lookup")
def lookup():
    return {"rows": find_user(request.args["name"])}  # SQL injection through a helper


if __name__ == "__main__":
    app.run(debug=True)  # debug mode
