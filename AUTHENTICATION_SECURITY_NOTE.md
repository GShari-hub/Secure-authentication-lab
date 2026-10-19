# Authentication Security Note

## Implemented design controls
1. **Password hashing:** Werkzeug scrypt password hashing; plaintext passwords are not stored.
2. **Server-side validation:** usernames use a restricted 3–32 character format; passwords must be 12–128 characters.
3. **Parameterized SQL:** user input is passed as SQL parameters.
4. **Generic authentication errors:** unknown usernames and wrong passwords return the same response.
5. **Rate limiting:** five login attempts per client key in a rolling 60-second window in this single-process demo.
6. **Session handling:** HttpOnly and SameSite=Lax cookies, a 15-minute permanent-session lifetime, and logout that clears the session.
7. **Cookie transport setting:** set `COOKIE_SECURE=1` when using HTTPS; it is off by default for localhost HTTP.
8. **Local-only service:** the development server binds to `127.0.0.1`.

## Automated test plan
Run `python -m pytest -q`. Tests check password hashing, input validation, login, protected-route access, generic errors, logout, and rate limiting. Save the actual output as evidence; these files do not prove that tests have already been run.

## Limitations
- This is an educational demo, not production-ready authentication.
- The in-memory rate limiter resets on restart and does not coordinate across workers. Production should use a shared limiter store.
- Flask's default session cookie is signed, not encrypted. Store only minimal, non-sensitive values in it.
- The fallback secret is for local testing only. Set a long random `SESSION_SECRET`; never commit it.
- Add CSRF protection for cookie-authenticated state-changing browser requests before production use.
- Use HTTPS and conduct a security review before any real deployment.
- Use synthetic accounts and data only.
