from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
import os
import csv
from io import StringIO
import joblib
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ================= LOAD ML MODEL =================
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ================= INIT DATABASE =================
def init_db():
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            text TEXT,
            result TEXT,
            confidence REAL,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= ML DETECTION =================
def detect_scam(job_text):
    vector = vectorizer.transform([job_text])
    prediction = model.predict(vector)[0]
    probability = model.predict_proba(vector)[0][1]
    confidence = round(probability * 100, 2)

    if prediction == 1:
        return "SCAM DETECTED ⚠️", "danger", confidence
    else:
        return "SAFE JOB ✅", "success", confidence


# ================= HOME =================
@app.route("/")
def home():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


# ================= USER DASHBOARD =================
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("SELECT result FROM history WHERE user_id = ?", (session["user_id"],))
    rows = cursor.fetchall()
    conn.close()

    total_scans = len(rows)
    fake_count = len([r for r in rows if "SCAM" in r[0]])
    real_count = len([r for r in rows if "SAFE" in r[0]])

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        total_scans=total_scans,
        fake_count=fake_count,
        real_count=real_count
    )


# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))

        conn = sqlite3.connect("history.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username or Email already exists!")

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")


# ================= SCAN PAGE =================
@app.route("/scan")
def scan():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("scan.html")


# ================= CHECK =================
@app.route("/check", methods=["POST"])
def check():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    job_text = request.form.get("job")
    result, color, confidence = detect_scam(job_text)
    india = pytz.timezone("Asia/Kolkata")
    now = datetime.now(india).strftime("%d-%m-%Y %H:%M:%S")

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO history (user_id, text, result, confidence, created_at) VALUES (?, ?, ?, ?, ?)",
        (session["user_id"], job_text, result, confidence, now)
    )

    conn.commit()
    conn.close()

    return render_template("result.html",
                           result=result,
                           color=color,
                           text=job_text,
                           confidence=confidence)


# ================= USER HISTORY =================
@app.route("/history")
def history():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT users.username, history.text, history.result,
               history.confidence, history.created_at
        FROM history
        LEFT JOIN users ON history.user_id = users.id
        WHERE history.user_id = ?
        ORDER BY history.id DESC
    """, (session["user_id"],))

    rows = cursor.fetchall()
    conn.close()

    return render_template("my_history.html", rows=rows)


# ================= ADMIN LOGIN =================
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "sudhesh" and password == "260206":
            session["admin"] = True
            return redirect(url_for("admin"))

        return render_template("admin_login.html", error="Invalid Admin Credentials")

    return render_template("admin_login.html")


# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT history.id, users.username, history.text,
               history.result, history.confidence, history.created_at
        FROM history
        LEFT JOIN users ON history.user_id = users.id
        ORDER BY history.id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    total = len(rows)
    scam = len([r for r in rows if "SCAM" in r[3]])
    safe = len([r for r in rows if "SAFE" in r[3]])

    avg_conf = round(sum(r[4] for r in rows) / total, 2) if total > 0 else 0

    return render_template(
        "admin.html",
        rows=rows,
        total=total,
        scam=scam,
        safe=safe,
        avg_conf=avg_conf
    )


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)