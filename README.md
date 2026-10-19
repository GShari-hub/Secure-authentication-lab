# Secure Authentication Lab

**Cyber Security internship task — local educational lab only.**

## Objective
Demonstrate password hashing, server-side validation, secure session cookies, logout, session expiry, login rate limiting, and generic authentication errors.

## Files
- `app.py` — small Flask authentication service.
- `tests/test_auth.py` — automated tests.
- `requirements.txt` — dependencies.
- `AUTHENTICATION_SECURITY_NOTE.md` — controls, test plan, limitations.
- `.gitignore` — excludes local files.

## Run on Windows PowerShell (Python 3.10+)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SESSION_SECRET="replace-with-a-long-random-local-secret"
python app.py
```
Open `http://127.0.0.1:5000`. The service binds to localhost only.

## Run tests
In another terminal with the virtual environment activated:
```powershell
python -m pytest -q
```
Save the actual output as evidence. Do not claim tests passed until you run them.

## Safety
Use synthetic accounts only. Never upload a real credentials database or secret key. This is a learning demo, not production-ready authentication software.
