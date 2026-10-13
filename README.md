# Secure Login System

A secure login web app built with Flask, SQLite and Argon2.

## Features
- User registration and login with **Argon2id** hashed passwords
- Input validation + **parameterized SQL queries** (SQL injection protection)
- Session management: HttpOnly/SameSite cookies, 15 min timeout, logout (POST)
- **Optional Two-Factor Authentication** (TOTP - Google Authenticator/Authy)
- Extras: CSRF tokens, account lockout after 5 failed logins, security headers, generic error messages

## Run
```bash
python -m venv venv
venv\Scripts\activate        # Windows  (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

For production set `SECRET_KEY` and `HTTPS=1` environment variables and serve over HTTPS.
