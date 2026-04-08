# Race Condition Attacks in Web Applications: Beyond Double-Spend

Companion code for the article **[Race Condition Attacks in Web Applications: Beyond Double-Spend](https://www.hunt-benito.com/race-condition-attacks-web-applications/)** published on [Hunt-Benito Limited](https://www.hunt-benito.com).

## Overview

This repository contains a deliberately vulnerable Flask application (**HBAuth**) that demonstrates **identity confusion through shared mutable state** — an exotic race condition pattern where per-request authentication state is stored in a module-level global variable, shared across all concurrent requests. When two users log in simultaneously, the attacker can end up authenticated as a different user.

The vulnerability mirrors the real-world **CVE-2026-33544** (Tinyauth OAuth identity confusion).

## Project Structure

```
├── hbauth/
│   └── hbauth.py                # Vulnerable application (Flask + 2FA)
├── hbauth-patched/
│   └── hbauth_patched.py        # Patched version (session-scoped state)
├── exploit/
│   └── exploit_identity_confusion.py   # Async exploit script
├── requirements.txt
└── README.md
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the vulnerable application
cd hbauth
python hbauth.py

# In another terminal, run the exploit
cd exploit
python exploit_identity_confusion.py
```

## Test Accounts

| Username | Password | Role | TOTP Secret |
|----------|----------|------|-------------|
| `alice` | `alice_pass` | admin | `JBSWY3DPEHPK3PXP` |
| `bob` | `bob_pass` | user | `K5QXY3LNQF35ZPHJ` |
| `mallory` | `mallory_pass` | user | `GXQT2NPELFLHOFLQ` |

## The Vulnerability

The vulnerable `hbauth.py` stores the authenticating user's ID in a module-level global (`pending_user_id`). Step 1 sets it, step 2 reads it. If two concurrent sessions overlap, step 2 reads the wrong user's ID.

```python
# Vulnerable: global shared state
pending_user_id = None  # Shared across ALL requests!

@app.route("/auth/step2")
def auth_step2():
    global pending_user_id
    # ...
    authenticated_user = get_user_by_id(pending_user_id)  # Reads shared state!
```

The patched version stores state in the Flask session (per-user signed cookie):

```python
# Patched: per-user session state
@app.route("/auth/step2")
def auth_step2():
    user_id = session.get("step1_user_id")  # Reads per-user state!
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/users` | List all users |
| `POST` | `/auth/step1` | Authenticate with username + password |
| `POST` | `/auth/step2` | Complete authentication with TOTP code |
| `GET` | `/profile` | View current session identity |
| `GET` | `/admin/dashboard` | Admin-only endpoint |
| `POST` | `/reset` | Reset application state |

## Generating TOTP Codes

```python
import pyotp
pyotp.TOTP("GXQT2NPELFLHOFLQ").now()  # Mallory's code
```

## License

Educational / security research purposes only. See the [article](https://www.hunt-benito.com/race-condition-attacks-web-applications/) for ethical considerations.
