"""Secure Login System - Flask + SQLite + Argon2 + optional TOTP 2FA."""
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
# Set SECRET_KEY in the environment for production; random key is dev-only.
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
ph = PasswordHasher()  # Argon2id by default
MAX_ATTEMPTS = 5
LOCK_MINUTES = 5
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )""")


# ---------- CSRF + security headers ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid CSRF token")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- validation ----------
def validate_registration(username, email, password):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-30 characters: letters, numbers, underscore.")
    if not EMAIL_RE.match(email) or len(email) > 254:
        errors.append("Enter a valid email address.")
    if len(password) < 8 or len(password) > 128:
        errors.append("Password must be 8-128 characters.")
    elif not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
              and re.search(r"\d", password)):
        errors.append("Password needs upper case, lower case and a digit.")
    return errors


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def start_session(user_id, username):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = validate_registration(username, email, password)
        if not errors:
            try:
                # Parameterized query -> SQL injection safe
                get_db().execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, ph.hash(password)))
                get_db().commit()
                flash("Account created. Please log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errors.append("Username or email already in use.")
        for e in errors:
            flash(e, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        generic = "Invalid username or password."

        if user and user["locked_until"] and \
                datetime.fromisoformat(user["locked_until"]) > datetime.now(timezone.utc):
            flash("Account temporarily locked. Try again later.", "error")
            return render_template("login.html")

        ok = False
        if user:
            try:
                ph.verify(user["password_hash"], password)
                ok = True
            except VerifyMismatchError:
                ok = False
        else:
            try:  # dummy verify to keep timing similar for unknown users
                ph.verify(ph.hash("dummy"), password)
            except VerifyMismatchError:
                pass

        if not ok:
            if user:
                attempts = user["failed_attempts"] + 1
                locked = None
                if attempts >= MAX_ATTEMPTS:
                    locked = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)).isoformat()
                    attempts = 0
                db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                           (attempts, locked, user["id"]))
                db.commit()
            flash(generic, "error")
            return render_template("login.html")

        db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
        db.commit()
        if user["totp_enabled"]:
            session.clear()
            session["pending_2fa"] = user["id"]
            return redirect(url_for("verify_2fa"))
        start_session(user["id"], user["username"])
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa")
    if not uid:
        return redirect(url_for("login"))
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        code = request.form.get("code", "").strip()
        if user and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            start_session(user["id"], user["username"])
            return redirect(url_for("dashboard"))
        flash("Invalid code.", "error")
    return render_template("verify_2fa.html")


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        secret = session.get("new_totp")
        code = request.form.get("code", "").strip()
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                       (secret, user["id"]))
            db.commit()
            session.pop("new_totp", None)
            flash("Two-factor authentication enabled.", "ok")
            return redirect(url_for("dashboard"))
        flash("Invalid code, try again.", "error")
    secret = session.setdefault("new_totp", pyotp.random_base32())
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureLogin")
    return render_template("setup_2fa.html", secret=secret, uri=uri)


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute("SELECT totp_enabled FROM users WHERE id=?",
                            (session["user_id"],)).fetchone()
    return render_template("dashboard.html", tfa=bool(user["totp_enabled"]))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=False)
