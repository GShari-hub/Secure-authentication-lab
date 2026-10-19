import os
import re
import sqlite3
import time
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = Path(os.environ.get("AUTH_DB_PATH", Path(__file__).with_name("auth_lab.db")))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET") or "LOCAL-TEST-ONLY-DO-NOT-DEPLOY",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=900,
    SESSION_REFRESH_EACH_REQUEST=False,
    MAX_CONTENT_LENGTH=16 * 1024,
)

ATTEMPTS = {}
WINDOW_SECONDS = 60
MAX_ATTEMPTS = 5


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )""")


def valid_username(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value))


def valid_password(value):
    return isinstance(value, str) and 12 <= len(value) <= 128


def generic_error():
    return jsonify({"error": "Invalid username or password"}), 401


def limited(key, now=None):
    now = time.time() if now is None else now
    attempts = [stamp for stamp in ATTEMPTS.get(key, []) if now - stamp < WINDOW_SECONDS]
    if len(attempts) >= MAX_ATTEMPTS:
        ATTEMPTS[key] = attempts
        return True
    attempts.append(now)
    ATTEMPTS[key] = attempts
    return False


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def prepare_db():
    init_db()


@app.get("/")
def index():
    return jsonify({"service": "Secure Authentication Lab", "scope": "local educational demo"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/register")
def register():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object required"}), 400
    username, password = payload.get("username"), payload.get("password")
    if not valid_username(username):
        return jsonify({"error": "Username must be 3-32 characters: letters, numbers, _, ., -"}), 400
    if not valid_password(password):
        return jsonify({"error": "Password must be between 12 and 128 characters"}), 400
    hashed = generate_password_hash(password, method="scrypt")
    try:
        with connect_db() as conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    except sqlite3.IntegrityError:
        return jsonify({"message": "If registration is allowed, the account can now be used"}), 202
    return jsonify({"message": "Account created"}), 201


@app.post("/login")
def login():
    key = request.remote_addr or "unknown"
    if limited(key):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return generic_error()
    username, password = payload.get("username"), payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return generic_error()
    with connect_db() as conn:
        user = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return generic_error()
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": "Login successful", "username": user["username"]})


@app.get("/me")
@login_required
def me():
    return jsonify({"username": session.get("username")})


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
