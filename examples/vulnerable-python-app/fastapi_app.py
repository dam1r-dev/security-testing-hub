import sqlite3

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


def get_db():
    return sqlite3.connect("app.db")


@app.get("/items/{item_id}")
def read_item(item_id: int, db=Depends(get_db)):
    return db.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchone()  # safe: item_id is an int


@app.get("/search")
def search(q: str, db=Depends(get_db)):
    return db.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'").fetchall()  # SQL injection


@app.get("/page", response_class=HTMLResponse)
def page(title: str):
    return HTMLResponse(f"<h1>{title}</h1>")  # XSS


@app.post("/run")
def run(cmd: str):
    import os

    os.system(cmd)  # command injection
