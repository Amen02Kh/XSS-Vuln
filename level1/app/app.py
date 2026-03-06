from flask import Flask, request, render_template, redirect, session, Response
import sqlite3
import os
import threading
import time
import secrets

app = Flask(__name__)
app.secret_key = "noteboard_secret"
DATABASE = "/tmp/noteboard.db"
FLAG = os.environ.get("FLAG", "CTF{5t0r3d_xss_c00k13_th3ft_4dm1n_b0t}")

# Admin session token — stored as a plain cookie named "session"
# Same cookie name as regular users, different value with higher privileges
ADMIN_SESSION = os.environ.get("ADMIN_SESSION", "4dm1n_5up3r_53cr3t_5e551on_t0k3n")

# ─────────────────────────── DB ───────────────────────────

def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token    TEXT NOT NULL
        );
        CREATE TABLE notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            author     TEXT NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    # Admin user with privileged session token
    c.execute(
        "INSERT INTO users (username, password, token) VALUES (?,?,?)",
        ("admin", "adm1n_p4ss", ADMIN_SESSION)
    )
    notes = [
        ("admin", "Welcome to NoteBoard",  "This is a public note board. Share your thoughts with the community!"),
        ("admin", "Maintenance Notice",    "Scheduled downtime this Saturday 02:00-04:00 UTC."),
        ("admin", "Security Reminder",     "Do not share your session cookies with anyone. Our admin reviews all posts."),
    ]
    for author, title, content in notes:
        c.execute("INSERT INTO notes (author, title, content) VALUES (?,?,?)", (author, title, content))
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ─────────────────────────── Session helpers ───────────────────────────

def get_token_from_request():
    """Read session token from plain cookie named 'session'."""
    return request.cookies.get("session", "")


def is_admin(token):
    return token == ADMIN_SESSION


# ─────────────────────────── Playwright Admin Bot ───────────────────────────

def admin_bot():
    """Real headless browser — visits /notes with admin session cookie every 20s."""
    time.sleep(5)
    while True:
        time.sleep(20)
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox"]
                )
                context = browser.new_context()
                context.add_cookies([{
                    "name":     "session",
                    "value":    ADMIN_SESSION,
                    "domain":   "127.0.0.1",
                    "path":     "/",
                    "httpOnly": False,
                }])
                page = context.new_page()
                page.goto("http://127.0.0.1:5000/notes", wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(3000)
                browser.close()
        except Exception as e:
            print(f"[bot error] {e}", flush=True)

# ─────────────────────────── Routes ───────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "All fields required."
        else:
            db = get_db()
            try:
                # Generate a unique session token per user
                token = secrets.token_hex(16)
                db.execute(
                    "INSERT INTO users (username, password, token) VALUES (?,?,?)",
                    (username, password, token)
                )
                db.commit()
                resp = redirect("/notes")
                # Set plain cookie named "session" — same name as admin's
                resp.set_cookie("session", token, httponly=False)
                return resp
            except Exception:
                error = "Username already taken."
            finally:
                db.close()
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        db.close()
        if user:
            resp = redirect("/notes")
            resp.set_cookie("session", user["token"], httponly=False)
            return resp
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    resp = redirect("/login")
    resp.delete_cookie("session")
    return resp


# 🔴 VULNERABLE — stored notes rendered raw (no escaping)
@app.route("/notes")
def notes():
    token = get_token_from_request()
    logged_in = False
    username = ""

    if token:
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE token=?", (token,)
        ).fetchone()
        db.close()
        if user:
            logged_in = True
            username = user["username"]

    db = get_db()
    all_notes = db.execute("SELECT * FROM notes ORDER BY id DESC").fetchall()
    db.close()

    # Flag only visible with admin session token
    flag = FLAG if is_admin(token) else ""

    return render_template("notes.html", notes=all_notes, flag=flag,
                           logged_in=logged_in, username=username)


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    token = get_token_from_request()
    if not token:
        return redirect("/login")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    db.close()
    if not user:
        return redirect("/login")

    error = None
    if request.method == "POST":
        title   = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or not content:
            error = "Title and content required."
        else:
            db = get_db()
            # ❌ content stored raw — no sanitization
            db.execute(
                "INSERT INTO notes (author, title, content) VALUES (?,?,?)",
                (user["username"], title, content)
            )
            db.commit()
            db.close()
            return redirect("/notes")
    return render_template("new_note.html", error=error)


if __name__ == "__main__":
    init_db()
    bot_thread = threading.Thread(target=admin_bot, daemon=True)
    bot_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False)

# Utility — wipe all user-posted notes, keep only admin seed notes
@app.route("/reset", methods=["POST"])
def reset():
    db = get_db()
    db.execute("DELETE FROM notes WHERE author != 'admin'")
    db.commit()
    db.close()
    return redirect("/notes")