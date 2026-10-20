import sqlite3
import subprocess

conn = sqlite3.connect("app.db")


def find_user(name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # the SQL is built here
    return cur.fetchall()


def find_user_safe(name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()


def run_report(kind):
    return subprocess.check_output("report --kind " + kind, shell=True)


def report_for(kind):
    return run_report(kind)  # one more hop
