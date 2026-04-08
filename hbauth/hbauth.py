import sqlite3
import hashlib
import time
import pyotp
from flask import Flask, request, jsonify, session, g

app = Flask(__name__)
app.secret_key = "hbauth-dev-secret-key-change-in-production"
DATABASE = "hbauth.db"

USERS = [
    {"id": 1, "username": "alice", "password": "alice_pass", "role": "admin",
     "totp_secret": "JBSWY3DPEHPK3PXP"},
    {"id": 2, "username": "bob", "password": "bob_pass", "role": "user",
     "totp_secret": "K5QXY3LNQF35ZPHJ"},
    {"id": 3, "username": "mallory", "password": "mallory_pass", "role": "user",
     "totp_secret": "GXQT2NPELFLHOFLQ"},
]

pending_user_id = None


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        "password_hash TEXT NOT NULL, role TEXT NOT NULL, "
        "totp_secret TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS sessions "
        "(id INTEGER PRIMARY KEY, user_id INTEGER, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
    )
    for u in USERS:
        pw_hash = hashlib.sha256(u["password"].encode()).hexdigest()
        db.execute(
            "INSERT OR IGNORE INTO users "
            "(id, username, password_hash, role, totp_secret) "
            "VALUES (?, ?, ?, ?, ?)",
            (u["id"], u["username"], pw_hash, u["role"], u["totp_secret"]),
        )
    db.commit()
    db.close()


def get_user_by_username(username):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def verify_totp(user_id, code):
    user = get_user_by_id(user_id)
    if not user:
        return False
    totp = pyotp.TOTP(user["totp_secret"])
    return totp.verify(code, valid_window=1)


@app.route("/users", methods=["GET"])
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/auth/step1", methods=["POST"])
def auth_step1():
    global pending_user_id

    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Username and password required"}), 400

    user = get_user_by_username(data["username"])
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    pw_hash = hashlib.sha256(data["password"].encode()).hexdigest()
    if pw_hash != user["password_hash"]:
        return jsonify({"error": "Invalid credentials"}), 401

    session["step1_user_id"] = user["id"]
    session["step1_complete"] = True

    pending_user_id = user["id"]

    return jsonify({
        "status": "pending_2fa",
        "user_id": user["id"],
        "username": user["username"],
        "message": "Submit 2FA code to /auth/step2",
    })


@app.route("/auth/step2", methods=["POST"])
def auth_step2():
    global pending_user_id

    if not session.get("step1_complete"):
        return jsonify({"error": "Complete step 1 first"}), 400

    step1_user_id = session.get("step1_user_id")

    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "2FA code required"}), 400

    if not verify_totp(step1_user_id, data["code"]):
        return jsonify({"error": "Invalid 2FA code"}), 401

    time.sleep(0.1)

    authenticated_user = get_user_by_id(pending_user_id)

    session.pop("step1_user_id", None)
    session.pop("step1_complete", None)
    session["authenticated"] = True
    session["user_id"] = authenticated_user["id"]
    session["username"] = authenticated_user["username"]
    session["role"] = authenticated_user["role"]

    return jsonify({
        "message": "Authentication successful",
        "user": {
            "id": authenticated_user["id"],
            "username": authenticated_user["username"],
            "role": authenticated_user["role"],
        },
    })


@app.route("/profile", methods=["GET"])
def profile():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify({
        "id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
    })


@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden — admin role required"}), 403

    return jsonify({
        "message": "Welcome to the admin dashboard",
        "admin_user": session["username"],
        "secrets": [
            "DATABASE_URL=postgresql://prod-db:5432/main",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
            "STRIPE_API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        ],
    })


@app.route("/reset", methods=["POST"])
def reset():
    global pending_user_id
    pending_user_id = None
    session.clear()
    return jsonify({"message": "State reset"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, threaded=True)
