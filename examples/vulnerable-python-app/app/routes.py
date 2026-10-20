from flask import Flask, request

from . import db as database
from .db import find_user, find_user_safe, report_for
from .service import UserService

app = Flask(__name__)


@app.route("/a")
def a():
    return {"rows": find_user(request.args["name"])}  # SQL injection in another file


@app.route("/b")
def b():
    return {"rows": database.find_user(request.args["name"])}  # through a module alias


@app.route("/c")
def c():
    return {"rows": find_user_safe(request.args["name"])}  # safe: bound parameter there


@app.route("/d")
def d():
    return report_for(request.args["kind"])  # command injection two hops away


@app.route("/e")
def e():
    return {"rows": UserService().lookup(request.args["term"])}  # a method of an imported class, which calls find_user
